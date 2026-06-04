# POC Report: V-009 JWT_SECRET Randomization on Restart

## Vulnerability Summary

**ID**: V-009  
**Type**: Cryptographic Failure / Improper Randomization  
**Severity**: High  
**Status**: True Positive (TP)

## Technical Details

### Root Cause
The `getJWTSecret()` function in `internal/config/config.go` (lines 310-323) generates a cryptographically random JWT secret each time the application starts if the `JWT_SECRET` environment variable is not configured.

```go
func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" { // No env var set
		b := make([]byte, 16)
		_, err := rand.Read(b)
		if err != nil {
			panic(fmt.Sprintf("failed to generate random JWT secret: %v", err))
		}
		secret = hex.EncodeToString(b)
	}
	return []byte(secret)
}
```

### Impact
- **Token Invalidation**: All JWT tokens issued before a restart become invalid after restart
- **Denial of Service**: Users are forcibly logged out on every service restart
- **Session Loss**: Active sessions are terminated without user action
- **API Breakage**: Integration tokens and API access tokens become unusable

### Attack Scenario
1. Attacker or operator restarts the Ech0 service (or service crashes/restarts naturally)
2. All existing JWT tokens are invalidated because the signing key changed
3. All authenticated users are logged out
4. All API integrations using tokens fail with 401 Unauthorized
5. Users must re-authenticate, causing service disruption

## Runtime Verification

### Test Environment
- Go version: 1.26+
- Platform: darwin
- Test date: 2026-05-14

### Verification Steps

**Step 1**: Simulate first startup without JWT_SECRET env var
```
First startup secret: 8cec1e313fc52fc41aa6068d459028bc
```

**Step 2**: Simulate second startup without JWT_SECRET env var
```
Second startup secret: 14a914a19c142c26c4bba0b3e901e48b
```

**Step 3**: Compare secrets
```
RESULT: Secrets are DIFFERENT (TP - vulnerable)
```

### Verification Result
✅ **CONFIRMED**: Each startup generates a different random secret when `JWT_SECRET` is not configured.

## Proof of Concept

A token signed with the first secret will fail validation with the second secret:
- Token issued at startup #1: signed with `8cec1e313fc52fc41aa6068d459028bc`
- Service restarts without `JWT_SECRET` env var
- Token validation at startup #2: fails because secret is now `14a914a19c142c26c4bba0b3e901e48b`
- Result: 401 Unauthorized for all previously valid tokens

## Remediation

### Recommended Fix
Require `JWT_SECRET` to be explicitly configured via environment variable. Fail fast during startup if not set:

```go
func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		panic("JWT_SECRET environment variable must be set")
	}
	return []byte(secret)
}
```

### Alternative Fix
Generate and persist the secret to a file on first startup:

```go
func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secretFile := "data/.jwt_secret"
		if data, err := os.ReadFile(secretFile); err == nil {
			return data
		}
		// Generate and persist
		b := make([]byte, 16)
		rand.Read(b)
		secret = hex.EncodeToString(b)
		os.WriteFile(secretFile, []byte(secret), 0600)
	}
	return []byte(secret)
}
```

## References

- **CWE-330**: Use of Insufficiently Random Values
- **CWE-347**: Improper Verification of Cryptographic Signature
- **OWASP**: A02:2021 – Cryptographic Failures

## Affected Code

- **File**: `internal/config/config.go`
- **Function**: `getJWTSecret()` (lines 310-323)
- **Called from**: `Config()` (line 184)

## Verification Artifacts

Test program output:
```
First startup secret: 8cec1e313fc52fc41aa6068d459028bc
Second startup secret: 14a914a19c142c26c4bba0b3e901e48b
RESULT: Secrets are DIFFERENT (TP - vulnerable)
```

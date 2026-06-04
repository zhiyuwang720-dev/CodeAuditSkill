# Go Web 项目漏洞清单

本文档供 web-vuln-audit skill 的 Phase 2 / Phase 3 使用。覆盖 Go Web 项目的常见高危/中危漏洞类型、sink 关键词、修复方向。

> **审计严重度范围：仅 High / Medium**，Low 不写入报告（详见主 `SKILL.md` 的核心约束）。

---

## 1. 适用范围

- Web Server：`net/http`、Gin、Echo、Fiber、Chi、Beego、Gorilla Mux
- API：REST / JSON / 文件上传 / 回调 Webhook
- 部署：容器/Kubernetes（含读取 Secret、RBAC 权限）

不覆盖（但可参考）：纯 CLI 工具、纯库项目。

---

## 2. 审计输入/输出

### 输入

- 代码仓库（含 `go.mod`、配置、部署清单、CI）
- 运行参数来源（环境变量/命令行/ConfigMap/Secret）
- 外部依赖：DB、Redis、K8s API、第三方 HTTP 服务

### 输出

直接使用 `references/audit-report-template.md` 产出报告（写入到被审计项目的 `reports/` 目录，详见 SKILL.md 核心约束）。

---

## 3. 快速建模（10~30 分钟）

### 3.1 找到"入口"

优先从以下位置开始：

- `main.go`：路由注册/中间件/监听端口/配置加载
- `router`/`handler`/`api`/`controller`：HTTP Handler
- 典型注册点：
  - `http.HandleFunc(...)` / `http.Handle(...)`
  - `mux.Router` / `chi.Router` / `gin.Engine` 路由表

目标产物：一张"入口清单"，至少包含：路径、方法、是否需要认证、读取的参数（query/body/header/path）。

### 3.2 识别信任边界

把数据源按信任级别分层（从不可信到相对可信）：

- HTTP 请求：`r.URL.Query()`、`r.FormValue()`、`json.NewDecoder(r.Body)`、Header/Cookie
- 外部系统：DB/Redis/K8s API/第三方 HTTP
- 配置：环境变量/配置文件/Secret（可能被误配导致风险）

### 3.3 列出高危"sink"（优先审计）

优先追这些调用链：

- 命令执行：`os/exec.Command*`、`syscall.Exec`
- 文件系统：`os.Open/WriteFile/MkdirAll/RemoveAll`（路径是否可控）
- SQL：`db.Query/Exec`、ORM 的 `Raw`、字符串拼接
- 模板/HTML：`html/template`、`template.HTML`、手写拼接
- 网络访问：`http.Get`、自建 `http.Client`（SSRF/超时/跳转）
- 反序列化：`gob`、`yaml`、`json`（字段注入/资源消耗）

---

## 4. Go Web 常见漏洞检查清单（按优先级）

### 4.1 认证/鉴权（最常见高危）

- 是否所有敏感接口都经过鉴权中间件（而不是"某些 handler 自己判断"）
- 是否存在"仅前端隐藏按钮"的越权（水平/垂直越权）
- Token/JWT：
  - 是否校验签名算法（避免 `alg=none`/算法混淆）
  - 是否校验 `exp`/`nbf`/`aud`/`iss`
  - 是否把用户可控字段直接当角色/权限
- Session/Cookie：
  - Cookie 是否设置 `HttpOnly`/`Secure`/`SameSite`
  - 登录态是否会固定（Session Fixation）

### 4.2 输入校验与注入

#### SQL 注入

- 高风险信号：`fmt.Sprintf("...%s...", userInput)` 拼接 SQL
- GORM: `db.Raw()` / `db.Where()` 是否传入拼接字符串？`db.Order(userInput)` 是否直接使用？
- 正确姿势：使用占位符 `?` / `$1`，或 ORM 参数化 API
- 注意：ORDER BY / LIMIT / 字段名 往往不能参数化，必须白名单

#### 命令注入

- 高风险信号：`exec.Command("sh", "-c", userInput)` `exec.CommandContext()` 或拼接 shell
- 修复方向：
  - 禁止 `sh -c`
  - 参数分离 + 白名单
  - 限制可执行文件与参数集合

#### 反射/结构体注入（Mass Assignment）

- `json.Unmarshal`/`Decoder.Decode` 直接解到"完整业务对象"时，检查：
  - 是否包含 `Role/IsAdmin/Status` 等敏感字段
  - 是否应使用"请求 DTO"结构体隔离

### 4.3 XSS / 模板注入
- 漏洞认定标准（本清单，仅计入 High/Medium）：
    - 仅将 **存储型 XSS** 视为漏洞：payload 被持久化（DB/缓存/对象存储等）并在后续页面渲染时触发
    - 触发条件需满足其一：
        - **无需认证** 即可触发（匿名访问即可看到并执行）
        - **普通用户可触发且影响到管理员权限/资产**（例如：管理员后台/运营平台查看时触发，导致会话劫持、Token 泄露或后台敏感操作被执行）
- 不计入漏洞（本清单范围内）：反射型 XSS、自触发（Self-XSS）、仅管理员自己提交/仅管理员可见的场景
- `html/template` 默认转义相对安全，但以下是高风险点：
  - `template.HTML` / `template.JS` / `template.URL`
  - 直接拼接 HTML 字符串返回
- 对 JSON API：确认前端是否把字段插到 `innerHTML`（跨项目协作时常见）


### 4.5 SSRF（Go 服务很常见）
- 漏洞认定标准（本清单）：
    - **仅能探测端口/内网存活不算 SSRF 漏洞**（例如通过超时/连接拒绝差异做端口扫描）
    - 必须至少满足一项，才计入 High/Medium：
        - **本机文件读取**：允许 `file:` / `jar:` 等协议并可读取系统/应用文件（配置、密钥、源码、`/etc/passwd` 等）
        - **内网 RCE 链**：可访问内网未授权服务并进一步实现远程代码执行，例如：Redis、Memcached 或 Java RMI 等服务的未授权访问/可利用能力组合
- 高风险入口：
  - 用户可控 URL，服务端 `http.Get(url)` / `client.Do(req)`
  - Webhook 回调、图片抓取、URL 预览
- 必查点：
  - 是否限制协议（仅 http/https）
  - 是否禁止访问内网/metadata（`169.254.169.254`、`127.0.0.1`、`::1`、RFC1918）
  - 是否限制重定向（`CheckRedirect`）
  - `http.Client` 是否有超时（避免资源耗尽）

### 4.6 路径穿越 / 任意文件读写

- 典型风险：用户输入参与拼接文件路径：`base + "/" + name`
- 修复方向：
  - `filepath.Clean` + 前缀校验
  - 使用白名单文件名/ID 映射
  - 避免 `..`、绝对路径、符号链接逃逸（需要额外约束）

### 4.7 敏感信息泄露

- 日志是否打印：密码、Token、证书私钥、K8s Secret
- 错误回显是否包含：SQL、内部路径、栈信息
- - 硬编码/泄露的密钥与凭据（统一归类到敏感信息泄露）：
    - 是否存在硬编码密钥（源码/配置仓库泄露风险），包括但不限于：JWT 签名密钥、加密密钥、第三方 API Key、Webhook Secret、AK/SK
    - JWT 相关敏感信息是否泄露：签名密钥、私钥、公钥配置、JWK、调试日志中输出的 Token
- Debug/pprof 是否暴露在公网


### 4.9 资源消耗类问题（DoS）

- `http.Server` 是否配置：`ReadTimeout/WriteTimeout/IdleTimeout`
- 请求体是否限制：`http.MaxBytesReader`
- `json.Decoder` 是否可能被大对象/深层结构拖垮

## 4.10: 供应链

**依赖组件速查** (仅 go.mod / go.sum 中存在时检查):

| 依赖 | 危险版本 | 漏洞类型 | 检查要点 |
|------|---------|---------|---------|
| golang.org/x/crypto | < 0.17.0 | 多种 | SSH/TLS 漏洞 |
| golang.org/x/net | < 0.17.0 | HTTP/2 DoS | rapid reset attack |
| golang.org/x/text | < 0.3.8 | DoS | 语言标签解析崩溃 |
| github.com/gin-gonic/gin | < 1.9.1 | 路径遍历 | 路径规范化绕过 |
| github.com/dgrijalva/jwt-go | 全版本(废弃) | 认证绕过 | 应迁移到 golang-jwt/jwt |
| github.com/go-yaml/yaml | < 3.0 | DoS | 递归解析内存耗尽 |
| github.com/tidwall/gjson | < 1.14.3 | DoS | 恶意 JSON 路径 |
| github.com/minio/minio | < RELEASE.2023-03-13 | 信息泄露 | 权限绕过 |
| gorm.io/gorm | < 1.25.0 | SQL 注入 | 特定条件下的注入 |
| google.golang.org/grpc | < 1.56.3 | DoS | HTTP/2 rapid reset |

**判定规则**:
- 危险版本 + 项目中实际使用了危险 API = **按对应 CVE 评级**
- 
---

## 5. 建议的静态扫描组合（辅助，不替代人工）

推荐工具（按收益排序）：

- `govulncheck`：依赖与标准库已知漏洞（Go 官方）
- `gosec`：常见安全模式扫描（命令执行、弱 TLS 等）
- `golangci-lint`：综合质量 + 部分安全规则

---

## 6. 漏洞写作要求

每条 High / Medium 漏洞至少包含：

- **标题**：类型 + 影响（例：SSRF 可访问云元数据）
- **严重度**：High / Medium（**Low 不写入**）
- **位置**：文件 + 函数 + 关键代码片段
- **触发条件**：输入点与到 sink 的数据流
- **影响**：数据泄露/权限提升/远程代码执行/DoS 等
- **修复建议**：可落地、带约束（白名单/参数化/超时）
- **验证方法**：修复后如何证明已解决（单测/手工请求）

完整结构见：`references/audit-report-template.md`

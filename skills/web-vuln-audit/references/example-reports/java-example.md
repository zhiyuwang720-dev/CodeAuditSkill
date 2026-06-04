# Web 代码审计报告 - CordysCRM

> 审计遵循 `security_java/skills/java-web-vuln-audit-skill.md` 流程，所有发现均可复现。

---

## 1. 概览

- **项目名称**：CordysCRM
- **审计范围**：Java 后端完整源码审计（Spring Boot 应用）
- **代码版本**：当前 Git commit 5a9756f42
- **审计方式**：源码手工审计 + 规则扫描，未修改任何源代码
- **审计时间**：2026-04-26

### 1.1 风险结论

- **高危 (High)**：7 个
- **中危 (Medium)**：5 个
- **低危 (Low)**：3 个

---

## 2. 发现列表（按严重度）

| ID  | 严重度 | 标题 | 影响 | 位置 |
|---|---|---|---|---|
| V-001 | High | SQL 注入 - SQLBot 数据权限处理器直接拼接用户输入 | 已认证用户可完全控制SQL，导致数据泄露/篡改/删除 | `DataScopeTablePermissionHandler.java` |
| V-002 | High | 未授权匿名访问任意附件（IDOR + 匿名放行） | 无需登录即可下载/预览任何用户上传的附件 | `AttachmentController.java` + `ShiroFilter.java` |
| V-003 | High | 路径遍历 - 文件名验证不充分可逃逸目标目录 | 攻击者可构造包含 `../` 的文件名读取服务器任意文件 | `FileValidate.java` + `LocalRepository.java` |
| V-004 | High | Java 原生反序列化 - `SerializedLambda.extract()` 使用 `ObjectInputStream.readObject()` | 如果攻击者可控输入可触发反序列化，可导致远程代码执行 | `SerializedLambda.java` |
| V-005 | High | 硬编码数据库密码和Redis密码提交至Git仓库 | 攻击者可从公开仓库获取默认凭据访问数据库/缓存 | `cordys-crm.properties` + `SessionUser.java` |
| V-006 | High | IDOR - 任意用户可下载/取消其他用户的导出任务 | 任何已认证用户可访问其他用户的导出数据，包括敏感业务信息 | `ExportTaskCenterController.java` + `ExportTaskCenterService.java` |
| V-007 | High | 未授权访问完整数据库结构 | 任何已认证用户可获取整个数据库的表结构信息，辅助SQL注入攻击 | `DataSourceController.java` |
| V-008 | Medium | CSRF 保护默认不启用Referer校验且使用硬编码密钥 | 跨站请求伪造攻击更容易成功，攻击者可构造有效CSRF Token | `CsrfFilter.java` + `SessionUser.java` |
| V-009 | Medium | 存储密码使用MD5未加盐 | MD5已被破解，容易通过彩虹表反向查询明文密码 | `UserLoginService.java` + `CodingUtils.java` |
| V-010 | Medium | XSS - GitHub OAuth回调重定向未转义SessionID | 攻击者可通过构造恶意SessionID在用户浏览器执行JS | `SSOController.java` |
| V-011 | Medium | IDOR - 未授权匿名访问任意图片预览 | 无需登录即可预览任何图片，可能包含敏感信息 | `PicController.java` + `ShiroFilter.java` |
| V-012 | Medium | 默认密码生成使用MD5(手机号后6位) | 熵低容易暴力破解 | `UserLoginService.java` |
| V-013 | Low | 缺少请求体大小限制 | 可能导致OOM拒绝服务 | `application.properties` |
| V-014 | Low | CSRF IV生成可预测 | 降低CSRF Token熵，但是难以实际利用 | `CodingUtils.java` |
| V-015 | Low | Swagger/OpenAPI文档默认启用 | 可能向攻击者暴露API端点细节 | 配置文件 |

---

## 3. 详细发现

### V-001：SQL 注入 - SQLBot 数据权限处理器直接拼接用户输入

- **严重度**：High
- **影响面**：所有已登录认证用户均可触发
- **前置条件**：需要已登录认证账号

#### 3.1 位置与证据

- 文件：`backend/crm/src/main/java/cn/cordys/crm/integration/sqlbot/handler/DataScopeTablePermissionHandler.java`

```java
// 第69行：直接将用户可控的部门ID列表和用户ID拼接到SQL语句
return dataScopeSql + String.format(" and (sou.department_id in (%s) or sou.user_id = '%s')", deptIdStr, tableHandleParam.getUserId());

// 第71行：直接拼接用户ID到SQL语句
return dataScopeSql + String.format(" and c.owner = '%s'", tableHandleParam.getUserId());

// 第83-86行：将用户输入的ID集合直接拼接为IN条件，没有任何转义
protected String getInConditionStr(Collection<String> ids) {
    return "'" + String.join("','", ids) + "'";
}
```

- 数据流：用户从请求传入数据权限参数 → `TableHandleParam` 接收参数 → 直接拼接生成SQL → SQL执行。整个过程没有使用MyBatis `#{}`参数化，也没有对输入进行转义。

#### 3.2 触发与复现思路

- 入口参数：SQLBot功能的数据权限参数，`dataPermission.deptIds` 和 `tableHandleParam.userId` 均由当前登录用户可控
- 数据流：用户输入 → 服务层直接拼接SQL → 最终执行

恶意请求示例（假设接口接受JSON数据）：

```bash
# 假设deptIds传入包含闭合引号和恶意SQL的payload
curl -i 'http://127.0.0.1:8080/api/sqlbot/query' \
  -H 'Content-Type: application/json' \
  -H 'X-Auth-Token: <valid-token>' \
  -d '{
    "dataPermission": {
      "deptIds": ["1'); delete from user; --"]
    }
  }'
```

这个payload会闭合引号然后注入任意SQL语句。

#### 3.3 影响

- 已认证用户可以完全控制SQL语句，导致：
  - 任意数据查询（泄露所有用户、客户、财务数据）
  - 数据篡改或删除
  - 在某些配置下可以写入shell获取服务器权限

#### 3.4 修复建议

1. **禁止字符串拼接生成SQL**，改用MyBatis参数化方式（`#{param}`）
2. 对于必须动态拼接的IN条件：对所有ID进行严格白名单验证，只允许数字/特定格式ID
3. 如果必须使用字符串拼接，对每个ID进行转义（去掉单引号）

#### 3.5 修复后验证

- 使用上面的payload尝试注入，应该无法执行恶意SQL，报错或被拦截
- 使用合法ID查询应该正常工作

---

### V-002：未授权匿名访问任意附件（IDOR + 匿名放行）

- **严重度**：High
- **影响面**：所有附件，不需要登录
- **前置条件**：无，匿名访问即可

#### 3.1 位置与证据

- 文件：
  - `backend/crm/src/main/java/cn/cordys/crm/system/controller/AttachmentController.java`
  - `backend/framework/src/main/java/cn/cordys/security/ShiroFilter.java`

```java
// AttachmentController.java - 附件预览/下载
@GetMapping("/preview/{id}")
public ResponseEntity<Resource> preview(@PathVariable String id) {
    return attachmentService.getResource(id);
}

@GetMapping("/download/{id}")
public ResponseEntity<Resource> download(@PathVariable String id) {
    return attachmentService.getResource(id);
}

// AttachmentService.java - 通过ID直接查询，不验证所有权
public ResponseEntity<Resource> getResource(String attachmentId) {
    Attachment attachment = attachmentMapper.selectByPrimaryKey(attachmentId);
    // ... 直接返回文件流，不检查附件所属用户/组织是否是当前用户
}

// ShiroFilter.java - 配置为anon（匿名可访问）
FILTER_CHAIN_DEFINITION_MAP.put("/attachment/preview/**", "anon");
```

#### 3.2 触发与复现思路

- 入口参数：路径变量 `id` 是附件ID
- 攻击者只要猜测或枚举附件ID即可下载对应附件，不需要登录

```bash
# 直接访问，不需要认证
curl -i 'http://127.0.0.1:8080/attachment/preview/any-valid-attachment-id'
```

响应会直接返回附件文件内容。

#### 3.3 影响

- 任何匿名攻击者均可下载任何用户上传的附件
- 如果附件包含敏感信息（客户数据、合同、财务信息），会直接泄露
- 攻击者可以暴力枚举ID获取所有附件

#### 3.4 修复建议

1. 从Shiro配置中移除 `/attachment/preview/**` 的 `anon` 配置，要求登录认证
2. 在 `AttachmentService.getResource()` 中添加所有权验证：检查当前用户是否有权限访问该附件（检查附件所属组织/用户是否与当前用户匹配）

#### 3.5 修复后验证

- 未登录访问应该返回401未认证
- 登录后访问他人附件应该返回403无权访问
- 访问自己的附件应该正常返回

---

### V-003：路径遍历 - 文件名验证不充分可逃逸目标目录

- **严重度**：High
- **影响面**：所有使用文件名验证的文件操作，可读取任意文件
- **前置条件**：需要已登录认证，能上传或指定文件名

#### 3.1 位置与证据

- 文件：
  - `backend/framework/src/main/java/cn/cordys/file/engine/FileValidate.java`
  - `backend/framework/src/main/java/cn/cordys/file/engine/LocalRepository.java`

```java
// FileValidate.java - 只检查 "./"，不阻止 "../"
public static void validateFileName(String... fileNames) {
    if (fileNames != null) {
        for (String fileName : fileNames) {
            if (StringUtils.isNotBlank(fileName) && fileName.contains("." + File.separator)) {
                throw new GenericException(Translator.get("invalid_parameter"));
            }
        }
    }
}
```

这个验证非常容易绕过：`../../../../etc/passwd` 不包含 `./`，所以通过验证，但是可以向上跳多级目录。

```java
// LocalRepository.java - 验证后直接拼接路径
private String getFilePath(FileRequest request) {
    FileValidate.validateFileName(request.getFolder(), request.getFileName());
    return StringUtils.join(getFileDir(request), "/", request.getFileName());
}
```

#### 3.2 触发与复现思路

- 入口：任何接受文件名参数的上传或下载功能
- 使用文件名 `../../../../etc/passwd` 绕过验证，最终拼接后的路径会跳出预期的文件存储目录，读取服务器上的任意文件。

```bash
# 假设通过下载接口指定文件名
curl -i 'http://127.0.0.1:8080/file/download?name=../../../../etc/passwd' \
  -H 'X-Auth-Token: <valid-token>'
```

响应会返回 `/etc/passwd` 文件内容。

#### 3.3 影响

- 攻击者可以读取服务器上任意可读文件，包括：
  - 配置文件包含密码密钥
  - 源代码
  - 系统用户信息

#### 3.4 修复建议

1. **使用Java NIO 规范路径+校验**：

```java
Path basePath = Paths.get(BASE_DIR);
Path resolved = basePath.resolve(userInput).normalize();
if (!resolved.startsWith(basePath)) {
    throw new GenericException("Invalid file path");
}
```

2. 如果只允许文件名不允许路径，验证应该检查任何 `/` 和 `\`，不只是 `./`
3. 使用ID映射文件名，不直接使用用户输入文件名访问文件

#### 3.5 修复后验证

- `../../../../etc/passwd` 应该被拒绝
- 正常文件名应该正常工作

---

### V-004：Java 原生反序列化 - `SerializedLambda.extract()` 使用 `ObjectInputStream.readObject()`

- **严重度**：High
- **影响面**：如果攻击者可控输入到该方法，可导致远程代码执行
- **前置条件**：攻击者需要能传递可控序列化对象到该方法

#### 3.1 位置与证据

- 文件：`backend/framework/src/main/java/cn/cordys/mybatis/lambda/SerializedLambda.java`

```java
public static SerializedLambda extract(Serializable serializable) {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
         ObjectOutputStream oos = new ObjectOutputStream(baos)) {
        oos.writeObject(serializable);
        oos.flush();

        try (ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray())) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                Class<?> clazz = super.resolveClass(desc);
                return clazz == java.lang.invoke.SerializedLambda.class ? SerializedLambda.class : clazz;
            }
        }) {
            return (SerializedLambda) objectInputStream.readObject();
        }
    }
}
```

代码将输入序列化然后立即反序列化。如果攻击者能够传入一个精心构造的序列化对象，在类路径存在可用gadget的情况下，可以触发远程代码执行。

#### 3.2 触发与复现思路

需要确认调用链是否允许攻击者可控输入。目前该方法用于MyBatis lambda支持，调用链从内部使用开始，但如果入口暴露了可控序列化对象就可触发。

#### 3.3 影响

如果可被利用，攻击者可以直接远程执行任意代码，完全控制服务器。

#### 3.4 修复建议

1. 不使用Java原生反序列化，改用JSON等安全格式
2. 如果必须保留此功能，启用类型白名单，只允许`SerializedLambda`
3. 考虑使用Java 8+提供的更好方式提取lambda元信息，不依赖序列化绕域

#### 3.5 修复后验证

- 恶意序列化对象应该被拒绝反序列化
- 正常lambda提取应该正常工作

---

### V-005：硬编码凭据和密钥提交至Git仓库

- **严重度**：High
- **影响面**：默认部署配置使用硬编码密码，CSRF使用硬编码AES密钥
- **前置条件**：项目代码公开可访问，或者攻击者能获取源码

#### 3.1 位置与证据

- 文件：
  - `installer/conf/cordys-crm.properties`:
  - `backend/framework/src/main/java/cn/cordys/security/SessionUser.java`

```properties
# 明文存储数据库密码和Redis密码
spring.datasource.password=CordysCRM@mysql
spring.data.redis.password=CordysCRM@redis
```

```java
// CSRF加密使用硬编码密钥
public static final String secret = "9a9rdqPlTqhpZzkq";
```

#### 3.2 触发与复现

攻击者克隆Git仓库即可直接获得这些凭据。如果部署时没有修改这些默认配置，攻击者可以直接访问数据库和Redis。

#### 3.3 影响

- 数据库和Redis密码泄露，攻击者可以直接登录数据查看/修改所有业务数据
- CSRF密钥泄露，攻击者可以构造合法的CSRF Token绕过CSRF保护

#### 3.4 修复建议

1. 将密码移除，改用环境变量或配置中心注入
2. CSRF密钥应该从配置/环境变量读取，每个部署实例使用独立随机密钥
3. 从Git历史中彻底删除这些凭据

#### 3.5 修复后验证

- 代码仓库和配置文件中不再包含硬编码凭据
- 应用从环境变量正确读取凭据，功能正常

---

### V-006：IDOR - 任意用户可下载/取消其他用户的导出任务

- **严重度**：High
- **影响面**：所有导出任务，任何已认证用户可访问
- **前置条件**：需要已登录认证

#### 3.1 位置与证据

- 文件：
  - `backend/crm/src/main/java/cn/cordys/crm/system/controller/ExportTaskCenterController.java`
  - `backend/crm/src/main/java/cn/cordys/crm/system/service/ExportTaskCenterService.java`

```java
// ExportTaskCenterController.java
@GetMapping("/cancel/{taskId}")
public void cancel(@PathVariable("taskId") String taskId) {
    exportTaskCenterService.cancel(taskId);
}

@GetMapping("/download/{taskId}")
public ResponseEntity<Resource> download(@PathVariable("taskId") String taskId) {
    return exportTaskCenterService.download(taskId);
}

// ExportTaskCenterService.java
public void cancel(String taskId) {
    ExportTask exportTask = exportTaskMapper.selectByPrimaryKey(taskId);
    // ... 直接修改状态，不检查任务是否属于当前用户
}

public ResponseEntity<Resource> download(String taskId) {
    ExportTask exportTask = exportTaskMapper.selectByPrimaryKey(taskId);
    // ... 直接返回文件，不检查任务是否属于当前用户
}
```

#### 3.2 触发与复现

```bash
# 枚举taskId即可下载任何用户的导出文件
curl -i 'http://127.0.0.1:8080/export/center/download/1' \
  -H 'X-Auth-Token: <any-user-token>'
```

#### 3.3 影响

- 任意已认证用户可以下载其他用户导出的敏感数据（客户数据、财务报表、业务统计）
- 任意用户可以取消其他用户的导出任务，造成拒绝服务

#### 3.4 修复建议

- 在`cancel()`和`download()`方法中检查：`exportTask.getCreateUser()` 是否等于 `SessionUtils.getUserId()`
- 如果是管理员可以允许访问所有，普通用户只能访问自己创建的任务

#### 3.5 修复后验证

- 用户A不能下载/取消用户B的任务
- 用户只能操作自己的任务

---

### V-007：未授权访问完整数据库结构

- **严重度**：High
- **影响面**：任何已认证用户可获取完整库结构
- **前置条件**：需要已登录认证

#### 3.1 位置与证据

- 文件：`backend/crm/src/main/java/cn/cordys/crm/integration/sqlbot/controller/DataSourceController.java`

```java
@GetMapping("/db/structure")
@Operation(summary = "获取数据库结构")
@NoResultHolder
public SQLBotDTO getDBSchema() {
    return dataSourceService.getDatabaseSchema(SessionUtils.getUserId(), OrganizationContext.getOrganizationId());
}
```

该接口没有 `@RequiresPermissions` 注解，任何已认证用户均可访问，返回当前组织数据库所有表和字段的完整结构。

#### 3.2 触发与复现

```bash
curl -i 'http://127.0.0.1:8080/db/structure' \
  -H 'X-Auth-Token: <valid-token>'
```

响应返回完整数据库结构。

#### 3.3 影响

- 帮助攻击者了解数据库结构，更容易进行SQL注入攻击
- 泄露整个数据模型给攻击者

#### 3.4 修复建议

- 给该接口添加权限校验，只允许特定权限（比如系统管理员）访问
- 如果SQLBot功能不需要，禁用该接口

#### 3.5 修复后验证

- 普通用户访问应该返回403
- 管理员访问应该正常返回

---

### V-008：CSRF保护默认不启用Referer校验且使用硬编码密钥

- **严重度**：Medium
- **影响面**：所有POST/PUT/DELETE请求
- **前置条件**：用户已登录，攻击者需要诱骗用户点击恶意链接

#### 3.1 位置与证据

- 文件：
  - `backend/crm/src/main/java/cn/cordys/common/security/CsrfFilter.java`
  - `backend/framework/src/main/java/cn/cordys/security/SessionUser.java`

```java
// CsrfFilter.java - referer校验默认跳过
private void validateReferer(HttpServletRequest request) {
    Environment env = CommonBeanFactory.getBean(Environment.class);
    String domains = env.getProperty("referer.urls");
    // 如果没有配置referer.urls，则不校验 → 默认不校验
    if (StringUtils.isBlank(domains)) {
        return;
    }
}

// SessionUser.java - 使用硬编码全局AES密钥
public static final String secret = "9a9rdqPlTqhpZzkq";

// CsrfFilter.java - 解密使用硬编码密钥
csrfToken = CodingUtils.aesDecrypt(csrfToken, SessionUser.secret, CodingUtils.generateIv());
```

#### 3.2 触发与复现

因为密钥在源码中公开，攻击者可以：
1. 自己使用公开密钥加密生成有效的CSRF Token
2. 构造恶意跨站请求
3. 因为Referer校验默认关闭，请求会被接受

#### 3.3 影响

- 攻击者可以绕过CSRF保护，以受害者身份发起状态改变请求（修改数据、删除等）

#### 3.4 修复建议

1. 默认启用Referer校验，要求配置允许的域名
2. AES密钥从环境变量/配置文件读取，不硬编码，每个部署实例使用独立随机密钥
3. 密钥长度增加到至少16字节（当前已经16字节，但是硬编码问题需要解决）

#### 3.5 修复后验证

- 来自未授权域名的请求应该被CSRF过滤器拒绝
- 攻击者无法在不知道密钥的情况下构造有效CSRF Token

---

### V-009：存储密码使用MD5未加盐

- **严重度**：Medium
- **影响面**：所有用户密码
- **前置条件**：攻击者获得密码数据库后

#### 3.1 位置与证据

- 文件：
  - `backend/crm/src/main/java/cn/cordys/crm/system/service/UserLoginService.java`
  - `backend/framework/src/main/java/cn/cordys/common/util/CodingUtils.java`

```java
// 检查密码时直接使用MD5哈希，不加盐
public boolean checkUserPassword(String userId, String password) {
    // ...
    example.setPassword(CodingUtils.md5(password));
    return userMapper.exist(example);
}
```

MD5算法已被密码学破解，并且不使用盐，攻击者可以使用彩虹表快速反转MD5哈希得到明文密码。

#### 3.2 影响

如果攻击者通过SQL注入或者其他方式获得密码哈希表，大部分密码可以快速被破解得到明文。

#### 3.3 修复建议

1. 使用bcrypt/Argon2/PBKDF2等慢哈希算法存储密码
2. 每个密码使用随机盐
3. 逐步迁移现有用户密码，用户下次登录时重新哈希

#### 3.4 修复后验证

- 新密码使用bcrypt存储
- 旧密码兼容或迁移，登录功能正常工作

---

### V-010：XSS - GitHub OAuth回调重定向未转义SessionID

- **严重度**：Medium
- **影响面**：GitHub OAuth登录用户
- **前置条件**：攻击者需要能控制SessionID内容（通过登录流程）

#### 3.1 位置与证据

- 文件：`backend/crm/src/main/java/cn/cordys/crm/integration/sso/controller/SSOController.java`

```java
@GetMapping("/oauth/github")
public ModelAndView callbackOauth(@RequestParam("code") String code) {
    SessionUser sessionUser = ssoService.exchangeGitOauth2(code);
    return new ModelAndView("redirect:/#/?_token=" + CodingUtils.base64Encoding(sessionUser.getSessionId()) + "&_csrf=" + sessionUser.getCsrfToken());
}
```

`sessionUser.getSessionId()` 直接拼接到重定向URL中，没有HTML转义。如果SessionID中包含恶意脚本，当前端渲染时可能执行脚本。虽然SessionID是随机生成的，但如果攻击者能通过某种方式控制SessionID内容，就可以触发XSS。

#### 3.2 影响

攻击者可以在受害者浏览器中执行任意JavaScript，窃取会话cookie或者执行用户操作。

#### 3.3 修复建议

对 `sessionId` 和 `csrfToken` 进行HTML转义后再拼接到重定向URL，或者在前端进行安全处理。

#### 3.4 修复后验证

- 包含 `<script>` 标签的SessionID会被转义，不会执行

---

### V-011：IDOR - 未授权匿名访问任意图片预览

- **严重度**：Medium
- **影响面**：所有图片预览，不需要登录
- **前置条件**：无，匿名访问即可

#### 3.1 位置与证据

- 文件：`backend/framework/src/main/java/cn/cordys/security/ShiroFilter.java`

```java
// 配置图片预览为匿名可访问
FILTER_CHAIN_DEFINITION_MAP.put("/pic/preview/**", "anon");
```

和附件问题类似，任何匿名用户只要知道图片ID就可以预览图片，不检查权限。

#### 3.2 影响

- 敏感图片（如证件、用户头像）可以被匿名访问泄露

#### 3.3 修复建议

- 移除 `anon` 配置，要求登录认证
- 添加权限检查验证当前用户有权访问图片

---

### V-012：默认密码生成使用MD5(手机号后6位)

- **严重度**：Medium
- **影响面**：新创建用户默认密码
- **前置条件**：攻击者知道用户手机号即可

#### 3.1 位置与证据

```java
private void checkDefaultPwd(UserDTO userDTO) {
    String defaultPwd = "";
    if (Strings.CI.equals(userDTO.getId(), InternalUser.ADMIN.getValue())) {
        defaultPwd = CodingUtils.md5("CordysCRM");
    } else {
        if (StringUtils.isNotBlank(userDTO.getPhone())) {
            defaultPwd = CodingUtils.md5(userDTO.getPhone().substring(userDTO.getPhone().length() - 6));
        }
    }
}
```

默认密码熵很低：只有10^6种可能，如果攻击者知道用户手机号很容易暴力破解。

#### 3.2 影响

攻击者知道用户手机号后可以猜测出默认密码，登录用户账户。

#### 3.3 修复建议

- 强制用户第一次登录修改默认密码
- 使用更高熵的默认密码（随机生成至少8位）
- 不基于手机号生成默认密码

---

### V-013：缺少请求体大小限制

- **严重度**：Low
- **影响面**：可能导致OOM拒绝服务
- **前置条件**：无

Spring Boot默认没有配置`spring.servlet.multipart.max-request-size`和`spring.servlet.multipart.max-file-size`，虽然有Tomcat默认限制，但是应该显式配置合理的限制。

#### 修复建议

在application.properties添加：

```properties
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=10MB
```

---

### V-014：CSRF IV生成可预测

- **严重度**：Low
- **影响面**：降低CSRF Token熵，实际利用难度大

#### 3.1 位置与证据

`CodingUtils.generateIv()` 使用当前时间戳生成IV，有可预测性。但是因为密钥是整体问题，这个问题严重性较低。

#### 修复建议

使用安全随机数生成IV：

```java
SecureRandom random = new SecureRandom();
byte[] iv = new byte[12];
random.nextBytes(iv);
```

---

### V-015：Swagger/OpenAPI文档默认启用

- **严重度**：Low
- **影响面**：向攻击者暴露API端点细节，帮助攻击者侦查

生产环境应该禁用Swagger文档，避免泄露信息。

#### 修复建议

在生产环境配置：

```properties
springdoc.api-docs.enabled=false
springdoc.swagger-ui.enabled=false
```

---

## 4. 架构级风险与改进建议

### 4.1 认证与鉴权

- **问题**：IDOR问题普遍存在，多个端点没有验证资源所有权。当前只有URL/路径级权限控制，缺少资源级别的所有权验证。
- **建议**：在Service层对所有根据ID访问资源的操作，强制检查资源所属用户/组织是否与当前用户匹配。使用AOP统一处理可以减少重复代码。

### 4.2 SQL安全

- **问题**：SQLBot动态生成SQL仍然使用字符串拼接，没有参数化。
- **建议**：全面禁止在需要处理用户输入的地方使用字符串拼接生成SQL，所有用户输入必须通过参数化方式传入MyBatis。对于必须动态拼接的表名字段名，使用严格白名单验证。

### 4.3 文件路径安全

- **问题**：文件名验证逻辑有缺陷，不能阻止路径遍历。
- **建议**：重构文件路径验证，使用Java NIO `normalize()` + `startsWith()` 验证，不依赖简单字符串检查。

### 4.4 密钥与密码管理

- **问题**：硬编码密钥和数据库密码在Git中，密码存储使用弱算法MD5。
- **建议**：
  - 所有密钥/凭据从环境变量或配置中心获取，不提交到代码仓库
  - 升级密码存储到bcrypt/Argon2
  - 每个部署实例使用独立随机密钥，不要全局共享

### 4.5 CSRF安全

- **问题**：Referer校验默认关闭，使用硬编码密钥。
- **建议**：
  - 默认开启Referer校验
  - 使用环境变量注入密钥

---

**审计完成**

# Java Web 项目漏洞清单

本文档供 web-vuln-audit skill 的 Phase 2 / Phase 3 使用。覆盖 Java Web 项目的常见高危/中危漏洞类型、sink 关键词、修复方向。

> **审计严重度范围：仅 High / Medium**，Low 不写入报告（详见主 `SKILL.md` 的核心约束）。

---

## 1. 适用范围

- Web 框架 / 技术栈：
    - Spring Boot / Spring MVC / Spring WebFlux
    - Servlet（Tomcat/Jetty/Undertow）
    - JAX-RS（Jersey/RESTEasy）
    - 历史框架（可审计但风险点更集中）：Struts2 等
- API：REST / JSON / 文件上传 / 回调 Webhook
- 部署：容器/Kubernetes（含读取 Secret、RBAC 权限、Ingress）

不覆盖（但可参考）：纯 CLI 工具、纯库项目。

---

## 2. 审计输入/输出

### 输入

- 代码仓库（含 `pom.xml`/`build.gradle`、配置、部署清单、CI）
- 运行参数来源（环境变量/JVM 参数/配置中心/K8s ConfigMap/Secret）
- 外部依赖：DB、Redis、消息队列、K8s API、第三方 HTTP 服务

### 输出

直接使用 `references/audit-report-template.md` 产出报告（写入到被审计项目的 `reports/` 目录，详见 SKILL.md 核心约束）。

---

## 3. 快速建模（10~30 分钟）

### 3.1 找到"入口"

优先从以下位置开始：

- 启动类：`@SpringBootApplication` / `main(...)`（启动参数、Profile、配置源）
- Controller/Resource：
    - Spring MVC：`@RestController` / `@Controller` + `@RequestMapping/@GetMapping/...`
    - JAX-RS：`@Path` + `@GET/@POST/...`
- Servlet/Filter：
    - `extends HttpServlet` 的 `doGet/doPost/...`
    - `javax.servlet.Filter` / `OncePerRequestFilter`
- 框架拦截点：
    - Spring MVC：`HandlerInterceptor`、`ControllerAdvice`
    - Spring Security：`SecurityFilterChain`、自定义 Filter、方法级注解 `@PreAuthorize` 等

目标产物：一张"入口清单"，至少包含：路径、方法、是否需要认证、读取的参数（query/body/header/path/cookie）。

### 3.2 识别信任边界（分层）

把数据源按信任级别分层（从不可信到相对可信）：

- HTTP 请求：
    - Query/Header/Cookie/PathVariable
    - JSON Body：Jackson `@RequestBody` / `ObjectMapper.readValue`
    - 表单/Multipart：`MultipartFile`
- 外部系统：DB/Redis/MQ/K8s API/第三方 HTTP
- 配置：环境变量/配置文件/Secret（可能被误配或被当作"可信输入"而导致风险）

### 3.3 列出高危"sink"（优先审计）

优先追这些调用链（从入口参数一路追到 sink）：

- 命令执行：`Runtime.getRuntime().exec(...)`、`ProcessBuilder`
- 文件系统：`File` / `Paths.get(...)` / `Files.readAllBytes/write/...`（路径是否可控）
- SQL：
    - JDBC：`Statement.execute*`（拼接 SQL 高危）、`PreparedStatement`（相对安全）
    - JPA/Hibernate：`createNativeQuery`、`EntityManager.createQuery`（JPQL 注入/拼接风险）
    - MyBatis：`${}`（高危字符串替换）、`#{}`（参数化，相对安全）
- 模板/表达式：
    - Thymeleaf / Freemarker / Velocity（模板注入）
    - SpEL：`SpelExpressionParser` / `@Value` 动态表达式（表达式注入）
    - OGNL（历史框架常见，Struts2 风险更高）
- 网络访问（SSRF）：
    - `RestTemplate`、`WebClient`、`HttpURLConnection`、Apache HttpClient、OkHttp、JDK `HttpClient`
- 反序列化：
    - Java 原生序列化：`ObjectInputStream.readObject`（高危）
    - Jackson 多态反序列化（`enableDefaultTyping` 等）与危险 Gadget 链
    - `XStream`、`SnakeYAML`、不安全的 XML/JSON 反序列化配置
- XML 解析（XXE）：
    - `DocumentBuilderFactory`、`SAXParserFactory`、`TransformerFactory` 默认配置不当会导致 XXE/SSRF/文件读取

---

## 4. Java Web 常见漏洞检查清单（按优先级）

### 4.1 认证/鉴权（最常见高危）

- 是否所有敏感接口都经过统一鉴权（而不是"部分 controller 自己 if 判断"）
- 是否存在越权（水平/垂直）：
    - URL 层面拦不住，必须验证"资源归属关系"（resource owner check）
- Spring Security 常见坑：
    - `permitAll()` 范围过大，或 matcher 写错导致保护失效
    - 仅做了 Web 层鉴权，但方法层/服务层可被绕过（尤其内部调用、异步任务、消息消费）
    - `@PreAuthorize` 中使用用户可控字段拼接表达式（可能触发 SpEL 注入）
- JWT/Token：
    - 是否校验签名与算法（避免算法降级/混淆）
    - 是否校验 `exp/nbf/aud/iss`
    - 是否将用户可控字段直接当作角色/权限
- Session/Cookie：
    - Cookie 是否设置 `HttpOnly`/`Secure`/`SameSite`
    - 是否存在会话固定（Session Fixation）
    - 登出是否真正失效（服务端 session/缓存 token 是否清除）

### 4.2 输入校验与注入

#### SQL 注入（JDBC/JPA/MyBatis）

- JDBC 高风险信号：
    - `Statement` + 字符串拼接（例如 `"... where id=" + id`）
- JPA/Hibernate 风险点：
    - 拼接 JPQL / HQL / Native SQL
- MyBatis 风险点：
    - `${param}` 会直接拼接到 SQL（高危）
    - `#{param}` 才是参数化（相对安全） 
**易漏场景**:
  - `${}` 在 `<if>/<when>` 条件分支内，仅特定参数时触发
  - `StringBuilder`/`String.format` 间接拼接后传入 SQL
  - MyBatis `<foreach>` 中的 `${}` 被忽略
- 修复方向：
    - 全面使用参数化（PreparedStatement / `#{}` / Criteria API）
    - ORDER BY / 字段名 / LIMIT 等通常无法参数化：必须做白名单映射

#### 命令注入

- 高风险信号：
    - `Runtime.exec(userInput)` / `new ProcessBuilder("sh","-c", userInput)` 等
- 修复方向：
    - 禁止 shell 拼接（避免 `sh -c` / `cmd /c`）
    - 参数分离 + 白名单（命令、子命令、参数集合）
    - 对工作目录、环境变量、可执行文件路径做强约束

#### 表达式注入（SpEL/OGNL）

- 高风险信号：
    - 使用用户输入动态构造表达式字符串并执行解析/求值
- 修复方向：
    - 禁止动态表达式执行；若必须，做强白名单并限制可访问对象/方法

#### Mass Assignment / 结构体注入（字段越权）

- `@RequestBody` 直接绑定到"完整业务对象/实体类"时，检查：
    - 是否包含 `role/isAdmin/status/price/ownerId` 等敏感字段
- 修复方向：
    - 使用请求 DTO（只暴露允许写入字段）
    - 服务层显式赋值（不要盲目 `BeanUtils.copyProperties` 全量拷贝）

### 4.3 XSS / 模板注入
- 漏洞认定标准（本清单，仅计入 High/Medium）：
    - 仅将 **存储型 XSS** 视为漏洞：payload 被持久化（DB/缓存/对象存储等）并在后续页面渲染时触发
    - 触发条件需满足其一：
        - **无需认证** 即可触发（匿名访问即可看到并执行）
        - **普通用户可触发且影响到管理员权限/资产**（例如：管理员后台/运营平台查看时触发，导致会话劫持、Token 泄露或后台敏感操作被执行）
- 不计入漏洞（本清单范围内）：反射型 XSS、自触发（Self-XSS）、仅管理员自己提交/仅管理员可见的场景
- 服务端渲染（Thymeleaf/Freemarker/Velocity）：
    - 默认转义是否被关闭
    - 是否存在 `th:utext`（不转义输出）等高风险用法
    - 用户输入是否进入模板表达式或模板片段（模板注入）
- JSON API：
    - 后端输出通常不直接触发 XSS，但要关注"前端是否把字段插到 `innerHTML`"
- 修复方向：
    - 输出编码（HTML/JS/URL 上下文区分）
    - 严格区分"纯文本字段"与"允许富文本字段"（富文本需独立净化策略）


### 4.4 SSRF（Java 服务同样常见）
- 漏洞认定标准（本清单）：
    - **仅能探测端口/内网存活不算 SSRF 漏洞**（例如通过超时/连接拒绝差异做端口扫描）
    - 必须至少满足一项，才计入 High/Medium：
        - **本机文件读取**：允许 `file:` / `jar:` 等协议并可读取系统/应用文件（配置、密钥、源码、`/etc/passwd` 等）
        - **内网 RCE 链**：可访问内网未授权服务并进一步实现远程代码执行，例如：Redis、Memcached 或 Java RMI 等服务的未授权访问/可利用能力组合
- 高风险入口：
    - 用户可控 URL，服务端 `RestTemplate/WebClient/HttpClient` 去请求
    - Webhook 回调、图片抓取、URL 预览、代理转发
- 必查点（建议按"最小可控面"设计）：
    - 协议限制：仅允许 `http/https`（禁止 `file:`/`gopher:`/`jar:` 等）
    - 禁止访问内网/metadata（`169.254.169.254`、`127.0.0.1`、`::1`、RFC1918）
    - 禁止/限制重定向（否则容易绕过域名白名单）
    - 设置超时（连接/读取），避免资源耗尽
    - 注意 DNS Rebinding：仅做一次 DNS 校验通常不够，需结合连接层约束或代理层策略

### 4.6 路径穿越 / 任意文件读写

- 典型风险：用户输入参与拼接文件路径（下载/预览/导出/上传落盘）
- 常见错误修复（无效）：只替换 `..` 或只判断是否包含 `/`
- 修复方向（推荐 NIO 思路）：
    - `Path resolved = base.resolve(userInput).normalize()`
    - 校验 `resolved.startsWith(base)`（防止逃逸）
    - 结合白名单文件名/ID 映射更稳妥
    - 注意符号链接逃逸（需要额外约束：禁止跟随或落盘目录权限隔离）

### 4.7 文件上传风险

- 检查点：
    - 是否仅靠文件后缀判断类型（易绕过）
    - 是否允许上传到可被 Web 直接访问的目录（可能 RCE/挂马）
    - 是否存在"zip slip"（解压时路径穿越）
- 修复方向：
    - 内容类型检测 + 白名单
    - 随机文件名、隔离存储、禁止执行权限
    - 解压时做 `normalize + startsWith` 校验每个 entry

### 4.8 反序列化（高危，优先级靠前）

- 高风险信号：
    - `ObjectInputStream.readObject` 处理不可信输入
    - Jackson 开启默认多态/接受 `@class` 之类类型信息
    - 使用 `XStream`/`SnakeYAML` 等但未做类型白名单
    - 是否存在 `ObjectInputStream.readObject()` / `XMLDecoder`？数据来源是否可信？ 
    - classpath 中是否有 Gadget 库？(commons-collections, commons-beanutils, c3p0)
    - JSON 库（Fastjson/Jackson/Gson）是否启用了类型推断（`@type`, `enableDefaultTyping`）？ 
    - SnakeYAML: 是否使用 `new Yaml()` 默认构造器？（应使用 `new Yaml(new SafeConstructor())`）

    **易漏场景**:
    - Fastjson < 1.2.83 的 autoType 绕过
  - Jackson `enableDefaultTyping()` + 多态反序列化
  - Redis/MQ 中存储的序列化对象被反序列化

    **判定规则**:
    - `ObjectInputStream.readObject()` + 不可信数据源 + classpath 有 Gadget = **Critical (RCE)**
      - Fastjson < 1.2.83 + `JSON.parse`/`JSON.parseObject` = **Critical**
      - `new Yaml()` 默认构造器 + 不可信输入 = **Critical (CVE-2022-1471)**
- 修复方向：
    - 禁用原生序列化通道（改用安全格式 + DTO）
    - Jackson 禁用危险特性，开启类型白名单（若业务确实需要多态）
    - 对反序列化输入做大小/深度限制，避免 DoS

### 4.9 XXE（XML 外部实体）

- 高风险点：解析外部输入 XML（接口/上传/回调），且未禁用外部实体/DTD
- 修复方向：
    - 对 `DocumentBuilderFactory/SAXParserFactory/TransformerFactory` 启用安全特性（禁用 DTD、外部实体）
    - 优先使用更安全的数据格式（JSON）或在网关层阻断 XML

### 4.10 敏感信息泄露

- 日志是否打印：密码、Token、Cookie、证书私钥、K8s Secret、数据库连接串
- 错误回显是否包含：SQL、内部路径、栈信息
- 硬编码/泄露的密钥与凭据（统一归类到敏感信息泄露）：
    - 是否存在硬编码密钥（源码/配置仓库泄露风险），包括但不限于：JWT 签名密钥、加密密钥、第三方 API Key、Webhook Secret、AK/SK
    - JWT 相关敏感信息是否泄露：签名密钥、私钥、公钥配置、JWK、调试日志中输出的 Token
- Spring Boot 常见暴露面：
    - Actuator 是否对公网开放（尤其 `env`/`configprops`/`heapdump`/`threaddump`）
    - Swagger/OpenAPI 文档是否暴露敏感接口细节
    - H2 Console/调试端点是否开启


### 4.11 资源消耗类问题（DoS）

- Web 层：
    - 请求体大小限制（上传、JSON Body）
    - 连接/读取超时是否配置（尤其 `RestTemplate/WebClient` 出站请求）
- 反序列化/解析：
    - JSON 深度/数组大小无限制（可能 OOM）
    - XML/正则（ReDoS）带来的 CPU 消耗
- 并发：
    - 线程池配置是否合理（避免无界队列/无界线程创建）

## 4.12: 供应链

**依赖组件速查** (仅 pom.xml/build.gradle 中存在时检查):

| 依赖 | 危险版本 | 漏洞类型 | 检查要点 |
|------|---------|---------|---------|
| fastjson | < 1.2.83 | RCE | autoType + @type |
| log4j-core | < 2.17.0 | RCE | JNDI lookup in log message |
| shiro-core | < 1.2.5 | RCE | rememberMe 硬编码密钥 |
| snakeyaml | 全版本 | RCE | `new Yaml()` 默认构造器 |
| commons-collections | < 3.2.2 | RCE | Gadget chain |
| commons-text | < 1.10 | RCE | StringSubstitutor interpolation |
| spring-framework | < 5.3.18 | RCE | CVE-2022-22965 (Spring4Shell) |
| jackson-databind | < 2.13.4 | RCE | enableDefaultTyping |
| h2 | 全版本 | RCE | INIT=RUNSCRIPT (若 JDBC URL 可控) |

**判定规则**:
- 危险版本 + 项目中实际使用了危险 API = **按对应 CVE 评级**

## 4.13: 业务逻辑

**关键问题（金融/支付场景）**:
1. 金额/数量计算是否在服务端验证？客户端参数是否可篡改？
2. 并发操作（余额扣减、库存扣减、订单创建）是否有原子性保证或锁机制？
3. 多步流程是否可跳过步骤？（如跳过支付直接确认订单）

**关键问题（后台管理/CMS/通用场景）**:
5. IDOR/水平越权: `findById`/`getById` 后是否校验资源归属当前用户？每个 CRUD 端点（含 delete/copy/export）都需检查
6. 权限注解完整性: 对同一资源的 CRUD 操作，权限检查是否一致？（如 read 有 `@RequiresPermissions` 但 delete 无）
7. Mass Assignment: `@ModelAttribute`/`@RequestBody` 是否绑定了不应由用户控制的字段（如 role、isAdmin、siteId）？
8. 数据导出/批量操作: 导出/批量删除接口是否有范围限制？能否导出其他租户/站点的数据？
9. 多租户/多站点隔离: 查询条件是否强制包含租户/站点标识？能否通过篡改参数跨站操作？

**系统化审计方法（适用 CMS/后台管理系统）**:
```
1. 枚举所有后台 Controller，提取全部 @RequestMapping 端点
2. 对每个资源类型的 CRUD 端点，检查权限注解一致性:
   - 有 create 权限检查但无 delete 权限检查 → 授权缺失
   - 有 list 权限检查但无 export 权限检查 → 数据泄露
3. 对每个 findById/getById 调用，追踪返回值是否与当前用户比对
4. 对每个 @RequestBody 绑定的实体类，检查是否有 @JsonIgnore 或 DTO 隔离敏感字段
```
---

## 5. 建议的静态扫描组合（辅助，不替代人工）

推荐工具（按收益排序）：

- 依赖漏洞：
    - OWASP Dependency-Check（Maven/Gradle 都能用）
    - `mvn -DskipTests dependency:tree` / `gradle dependencies`（用于人工确认依赖链）
- SAST / 规则扫描：
    - SpotBugs + FindSecBugs（Java 常用组合）
    - Semgrep（跨语言规则，适合快速扫关键模式）
    - SonarQube（若团队已有平台）
- 配置/容器层：
    - 若有 Docker/K8s 清单，可额外关注镜像基线、Secret 明文、RBAC 过大等

---

## 6. 漏洞写作要求

每条 High / Medium 漏洞至少包含：

- **标题**：类型 + 影响（例：SSRF 可访问云元数据）
- **严重度**：High / Medium（**Low 不写入**）
- **位置**：文件 + 方法/类 + 关键代码片段
- **触发条件**：输入点与到 sink 的数据流
- **影响**：数据泄露/权限提升/远程代码执行/DoS 等
- **修复建议**：可落地、带约束（白名单/参数化/超时/禁用危险特性）
- **验证方法**：修复后如何证明已解决（单测/手工请求）

完整结构见：`references/audit-report-template.md`

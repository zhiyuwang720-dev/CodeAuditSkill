# 漏洞验证质疑问题清单

供 web-vuln-audit skill 的 **Phase 4 子 Agent** 使用，对每条 High / Medium 漏洞做可利用性验证。

## 使用方法

1. 子 Agent 拿到一条漏洞信息（ID / 标题 / 严重度 / 位置 / 复现思路）
2. 按下方 **通用 5 问（Q-G1~Q-G5）** 逐项作答
3. 根据漏洞类型，追加 **专项追问**（4.1~4.10 任一组）
4. **每个答案必须带 `file:line` 证据**（grep 或读源码定位）
5. 尝试按 README 拉起 docker 环境，发实际 HTTP 请求复现；失败降级为静态推理
6. 综合给出最终判定：**TP（真实漏洞）** 或 **FP（误判）**
7. 调用 `references/poc-report-template.md` 或 `references/false-positive-template.md` 写报告

---

## 1. 通用 5 问（每条漏洞必答）

### Q-G1：用户可控的输入是否真的能到达 sink？

- 答题要求：给出**完整数据流证据链**，从入口（HTTP 参数读取）到 sink（exec / SQL / 文件 / 网络等），每一跳都标注 `file:line`
- 期望格式：`r.FormValue("x") @ controller.go:42 → validateInput @ service.go:88 → exec.Command(..., x) @ runner.go:15`

### Q-G2：用户输入是否被有效清理（allow list / escape / 类型校验 / 参数化）？

- 答题要求：定位校验代码（如有），判断是否真的阻断了攻击载荷
- 注意「无效清理」的常见模式：
  - 只校验长度不校验内容
  - 只 `Replace("..", "")` 不校验绝对路径
  - 只校验首字符不校验整体
  - 黑名单 / 正则有遗漏

### Q-G3：代码是否处于测试 / 演示 / 死代码 / 自动生成上下文？

- 答题要求：判断该 sink 所在文件是否：
  - 在测试目录（`*_test.go` / `src/test/`）
  - 在 `examples/` / `demo/` / `playground/`
  - 是否为 `*.pb.go` / `*_gen.go` 等自动生成代码
  - 路由是否真的被注册到生产 HTTP server（grep 注册点）

### Q-G4：漏洞触发是否需要前置条件？

- 答题要求：明确列出触发链所需条件：
  - 是否需要登录？需要什么角色？（管理员？普通用户？）
  - 是否依赖特定配置（如某 feature flag 开启）
  - 是否需要前序漏洞作为跳板（如先绕过鉴权）
  - 是否需要特定数据状态（如某行记录已存在）

### Q-G5：是只能理论上存在威胁，还是可复现可利用？

- 答题要求：综合 G1~G4，给出可利用性等级：
  - **可直接利用**：无门槛，可立即构造 PoC 触发
  - **有条件可利用**：满足明确的前置条件后可利用（条件本身现实可达成）
  - **理论存在但难以利用**：路径成立但需要苛刻条件或特殊时序
  - **不可利用**：路径在生产环境中不可达

---

## 2. 漏洞类型专项追问

根据漏洞主类型从下方选一组追问。

### 2.1 命令注入（Command Injection）

- Q-C1：命令是否数组形式执行（`exec.Command("ls", arg)` ）还是字符串拼接（`bash -c "ls " + arg`）？
- Q-C2：是否使用 `sh -c` / `cmd /c` 子 shell？（如有则元字符可注入）
- Q-C3：是否对命令元字符（`; & | ` $ \\``）做转义或拒绝？
- Q-C4：可执行文件路径是否可控？（含 `PATH` 注入）

### 2.2 SQL 注入

- Q-S1：是否使用参数化（`?` / `$1` / PreparedStatement / MyBatis `#{}`）？
- Q-S2：是否存在拼接（`Sprintf("WHERE id=%s", id)` / `Statement.execute("... " + x)` / MyBatis `${}`）？
- Q-S3：ORDER BY / LIMIT / 表名/列名 是否走白名单映射？
- Q-S4：错误回显是否泄露 SQL / 结构信息？（影响盲注难度）

### 2.3 SSRF

- Q-R1：URL 协议是否限制（仅 http/https）？是否禁止 `file:` / `gopher:` / `jar:` / `dict:`？
- Q-R2：是否屏蔽内网 / loopback / 链路本地（`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`、`::1`、`fe80::/10`）？
- Q-R3：是否解析 hostname 后再校验 IP（防 DNS Rebinding）？
- Q-R4：是否会回显响应体（影响数据外带能力）？
- Q-R5：是否限制/禁止重定向（`CheckRedirect`）？是否限制超时？

### 2.4 路径穿越

- Q-P1：是否 `filepath.Clean` / `Path.normalize()` + 前缀校验（`startsWith(base)`）？
- Q-P2：是否仅做了 `Replace("..", "")`（无效）？是否拒绝绝对路径？
- Q-P3：是否考虑符号链接逃逸（落盘后被指向 base 外）？
- Q-P4：白名单文件名 / ID 映射是否实施？

### 2.5 XSS / 模板注入

- Q-X1：渲染上下文是 HTML / JS / URL / CSS 哪一种？默认转义是否覆盖？
- Q-X2：是否使用 `template.HTML` / `th:utext` / `{{{ }}}` 等"信任原文"标签？
- Q-X3：富文本字段是否经过净化（DOMPurify / OWASP Java HTML Sanitizer）？
- Q-X4：JSON API 字段是否被前端 `innerHTML` 插入？

### 2.6 CSRF / CORS

- Q-F1：是否存在 CSRF Token / Origin 校验 / SameSite Cookie？
- Q-F2：CORS 配置是否同时出现 `Allow-Origin: *` + `Allow-Credentials: true`（致命组合）？
- Q-F3：Origin 白名单是否包含通配子域 / 用户可控子域？

### 2.7 反序列化（Java）

- Q-D1：是否使用 `ObjectInputStream.readObject` 处理不可信输入？
- Q-D2：Jackson 是否开启 `enableDefaultTyping` / 接受 `@class`？
- Q-D3：XStream / SnakeYAML 是否做类型白名单？
- Q-D4：classpath 中是否存在常见 gadget 链组件（Commons Collections / Spring 等）？

### 2.8 XXE（Java）

- Q-E1：`DocumentBuilderFactory` / `SAXParserFactory` / `TransformerFactory` 是否禁用 DTD（`disallow-doctype-decl`）和外部实体（`external-general-entities`、`external-parameter-entities`）？
- Q-E2：是否能读到 `file://`、`http://内网` 等？
- Q-E3：错误信息是否回显（影响外带 vs 盲打）？

### 2.9 表达式注入（SpEL / OGNL）

- Q-T1：是否使用用户输入构造 `SpelExpressionParser.parseExpression(userInput)` 或类似？
- Q-T2：表达式上下文是否能访问 `Runtime` / `T(java.lang.Runtime)` 等危险类？
- Q-T3：是否在 `@PreAuthorize` / `@Value` 等注解中拼接用户输入？

### 2.10 文件上传

- Q-U1：是否仅靠后缀名校验类型？（易绕过）
- Q-U2：上传目录是否可被 Web 直接访问执行（PHP / JSP / ASP）？
- Q-U3：是否做内容类型嗅探 + magic bytes 校验？
- Q-U4：解压逻辑是否防 zip slip（每个 entry 路径都 `normalize + startsWith`）？

---

## 3. 真实运行复现（强烈推荐执行）

按以下步骤尝试真实拉起环境：

1. **读 README**：`cat {target_project}/README.md` 或 `README_zh.md` / `INSTALL.md`
2. **提取启动指令**，常见模式：
   - `docker run ...`
   - `docker-compose up -d` / `docker compose up -d`
   - `make run` / `make up`
   - `go run cmd/server/main.go`
   - `mvn spring-boot:run` / `./mvnw spring-boot:run`
   - `./gradlew bootRun`
3. **执行启动**，等待服务就绪（轮询健康检查端口）
4. **构造 PoC**：根据 Q-G1~G4 答案设计载荷
5. **发请求**：`curl -i ...`，记录响应
6. **判定**：
   - 响应中能观察到漏洞利用证据（命令输出 / SQL 错误 / 内网响应 / 文件内容） → ✅ 已运行验证 = TP
   - 响应被拦截 / 报错与预期不符 → 复核数据流；可能是 FP，也可能是 PoC 构造问题
7. **环境无法搭建**（无 docker / 编译失败 / 依赖缺失）→ 降级为静态推理，在 PoC 报告中显式标注「未运行验证，仅静态推理」

---

## 4. 判定规则与示例

### 4.1 判定规则

- **TP（True Positive）**：
  - G1 答"是"且数据流完整
  - G2 答"无有效清理"或"清理可绕过"
  - G3 答"否"（不在测试/死代码上下文）
  - G5 至少为「有条件可利用」
- **FP（False Positive）**：满足以下任一即可判 FP：
  - G1 答"否"（数据流不通）
  - G2 答"已被有效清理"（提供具体清理代码片段证明）
  - G3 答"是"（测试/死代码/未注册路由）
  - G5 答"不可利用"

### 4.2 标准回答样例（命令注入场景）

> 来源：PRD 示例（真实漏洞 TP 判定）

```
Q-G1: 用户可控的输入是否到达命令/代码执行汇点？
→ 是。r.FormValue("password") 流向 userCreate 并进入 runBash(fmt.Sprintf(..., password))
  (main.go:289-296, main.go:1053-1055)。

Q-G2 / Q-C1: 这是否是使用用户数据的代码评估（eval/exec）？命令是否数组形式执行？
→ 否。这是进程执行（runBash 调用 exec.Command）(helpers.go:35-38)。
→ 否。runBash 使用单个命令字符串调用 bash -c (helpers.go:35-38)。

Q-G2 / Q-C3: 用户输入是否被有效清理（允许列表、转义）？
→ 否。validatePassword 仅强制执行最小长度，不转义 shell 元字符 (main.go:932-936)。

Q-G3: 代码是否处于测试/演示/死代码/生成的上下文中？
→ 否。该处理器注册在主 HTTP 服务器设置中 (main.go:578-582)。

→ 综合判定：真实漏洞 (TP)
→ 运行验证：✅ 已通过 docker-compose up 启动，POST /create?password='$(id)' 收到 uid=1000(...) 响应
```

### 4.3 FP 判定示例

```
Q-G1: 用户可控输入是否到达 sink？
→ 否。看似的入口 r.URL.Query().Get("cmd") 在 handler.go:55 被调用，但该 handler 仅在
  internal/cli/test_only.go 中通过 if os.Getenv("DEV_MODE") == "1" 注册（dev 模式专用），
  生产构建 tag 排除该文件。

Q-G3: 代码是否处于测试/演示/死代码/生成的上下文中？
→ 是。文件 build tag 为 `//go:build dev`，生产环境不编译。

→ 综合判定：误判 (FP)
→ 误判原因：sink 仅在开发模式下注册，生产环境路由不可达。
```

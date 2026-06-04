# Web 代码审计报告模板（Go / Java 通用）

> 适用于 web-vuln-audit skill 输出的主审计报告。**只记录 High / Medium 漏洞**。
> 建议每条问题都做到"别人照着你的文字能复现"。

---

## 1. 概览

- 项目名称：
- 项目类型：Go / Java / mixed
- 主要技术栈：（Gin / Spring Boot / Echo / ...）
- 审计范围：
- 代码版本（commit/tag）：
- 审计方式：源码审计 / 依赖扫描 / 规则扫描 / 手工验证
- 审计时间：


### 1.1 风险结论

- 高危（High）：X 个
- 中危（Medium）：X 个

> 本报告**不收录**低危（Low）漏洞。Low 在审计过程中已被识别但不写入报告，详见 web-vuln-audit skill 的严重度边界定义。

---

## 2. 发现列表（按严重度）

| ID | 严重度 | 标题 | 影响 | 位置 |
|---|---|---|---|---|
| V-001 | High |  |  |  |
| V-002 | High |  |  |  |
| V-003 | Medium |  |  |  |

---

## 2.5 项目文件树与审计覆盖

说明：

- 列出项目**全部目录到文件**
- **仅源码文件**（`.go` / `.java` / `.kt` / `.scala`）标记 `(审计)` / `(未审计)`
- 配置、文档、资源、测试桩等其他文件类型不打审计标记
- 自动生成文件（如 `*.pb.go`、`*_gen.go`、`generated/`）即使是源码也无需打标记
- Phase 3 审计后标记为 `(审计)` 的文件，Phase 3.5 可进一步覆盖更多 `(未审计)` 文件

示例格式：

```
project/
├── README.md
├── go.mod
├── conf/
│   └── app.yaml
├── internal/
│   ├── controller/
│   │   ├── user_controller.go        (审计)
│   │   ├── ai_controller.go          (审计)
│   │   └── debug_controller.go       (未审计)
│   └── service/
│       └── user_service.go           (未审计)
├── pkg/
│   └── htmltext/
│       └── htmltext.go               (审计)
└── plugin/
    └── README.md
```

Java 示例：

```
project/
├── README.md
├── pom.xml
├── src/
│   ├── main/
│   │   ├── java/com/example/
│   │   │   ├── controller/
│   │   │   │   ├── UserController.java       (审计)
│   │   │   │   └── FileController.java       (审计)
│   │   │   └── service/
│   │   │       └── UserService.java          (未审计)
│   │   └── resources/
│   │       └── application.yml
│   └── test/
│       └── java/com/example/
│           └── UserControllerTest.java
└── Dockerfile
```

---

## 3. 详细发现

> 以下发现来源于 Phase 3 主审计和 Phase 3.5 二次扫描的合并结果。
> 编号 V-001~V-N 由 Phase 3 产生，V-{N+1}+ 由 Phase 3.5 追加。
> Phase 3.5 发现的系统性缺陷（同类型 ≥3 实例）记录于 §4 架构风险。

### V-001：标题（类型 + 影响）

- **严重度**：High / Medium
- **影响面**：哪些角色/接口/数据会受影响
- **前置条件**：需要登录吗？需要什么权限？需要特定配置吗？

#### 3.1 位置与证据

- 文件：`path/to/file.go` 或 `path/to/File.java`
- 函数/方法：`func Name(...)` 或 `ClassName#methodName(...)`

```go
// 关键代码片段（建议包含上游输入点与下游 sink）
// Go 项目使用 ```go 代码块；Java 项目使用 ```java
```

如涉及配置（Java 项目常见）：

- 配置文件：`application.yml` / `application.properties`

```yaml
# 关键配置片段（例如：CORS/CSRF/Actuator 暴露面/安全开关）
```

#### 3.2 触发与复现思路

- 入口参数：来自哪里（query/body/header/path/cookie）
- 数据流：输入如何到达危险点（拼接/透传/未校验/表达式执行）

复现请求示例（如适用）：

```bash
# 关键步骤：构造请求并命中漏洞点
# curl 示例（按实际接口替换 URL、Header、Body）
curl -i 'http://127.0.0.1:8080/api/xxx?param=PAYLOAD'
```

#### 3.3 修复建议

- 建议 1：
- 建议 2：

#### 3.4 修复后验证

- 单元测试/集成测试建议：
- 手工验证要点：

---

## 4. 架构级风险与改进建议（可选）

- 认证/鉴权模型（中间件 / Spring Security / 自研网关）
- Secret 管理与最小权限（RBAC）
- 日志与审计（敏感字段脱敏、错误回显边界）
- 限流与超时（入站/出站）
- 运维端点暴露面（Actuator / Swagger / pprof / Debug）

### 系统性缺陷（Phase 3.5 识别，同类型 ≥3 实例）

> 以下条目由 Phase 3.5 二次扫描生成。当同一漏洞类型在 ≥3 处代码位置被发现时，
> 表明项目存在该漏洞类型的系统性缺陷，需要全局统一的修复策略而非单点修补。

| 漏洞类型 | 实例数 | 关联 V-ID | 影响模块 | 根因摘要 |
|---------|-------|----------|---------|---------|
| {类型}  | {N}   | V-XXX,...| {模块}  | {根因}  |

每项系统性缺陷应包含全局修复建议（非单点修复），单独成段写入对应条目下方。

---

## 5. 验证结果（Phase 4 完成后自动填充）

每个 High / Medium 漏洞经过并行子 Agent 验证后，结果汇总于此表：

| ID | 标题 | 判定 | 是否运行验证 | 详细报告 |
|---|---|---|---|---|
| V-001 |  | TP / FP | ✅ 已运行 / ❌ 仅静态 | [poc-V-001.md](poc-V-001.md) 或 [fp-V-001.md](fp-V-001.md) |
| V-002 |  |  |  |  |

**字段说明：**
- **判定**：TP = True Positive（真实漏洞），FP = False Positive（误判）
- **是否运行验证**：✅ 表示按 README docker 启动方式真实拉起环境并复现成功；❌ 表示因环境/依赖缺失降级为静态推理
- **详细报告**：TP 链接到 `poc-V-{ID}.md`（PoC 步骤），FP 链接到 `fp-V-{ID}.md`（误判原因）

### 验证统计

- 总漏洞数：X
- TP（确认漏洞）：X 个（其中 ✅ 运行验证 X 个，❌ 静态推理 X 个）
- FP（确认误判）：X 个

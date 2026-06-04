---
name: web-vuln-audit
description: Web 项目安全代码审计 skill，自动识别 Go / Java / Python / PHP / JavaScript 项目类型并加载对应漏洞清单（SQL/SSRF/XSS/CSRF/反序列化/路径穿越/鉴权/命令注入/XXE 等），输出审计报告到被审计项目的 reports/ 目录。适用于：(1) 单仓库 Web 项目的中高危漏洞扫描，(2) 自动生成可复现的漏洞报告（含代码位置、复现 curl、修复建议、修复后验证），(3) 对每条漏洞并行启动子 Agent 进行可利用性验证，输出 PoC 步骤或误判说明。只审计 High/Medium，跳过 Low。
tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Task
priority: high
file_patterns:
  - "**/*.java"
  - "**/*.go"
  - "**/*.kt"
  - "**/*.scala"
  - "**/*.py"
  - "**/*.php"
  - "**/*.js"
  - "**/*.ts"
  - "**/*.jsx"
  - "**/*.tsx"
  - "**/*.xml"
  - "**/*.yml"
  - "**/*.yaml"
  - "**/*.json"
  - "**/*.properties"
  - "**/Dockerfile"
exclude_patterns:
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/.git/**"
  - "**/test/**"
  - "**/tests/**"
  - "**/node_modules/**"
---

# Web 项目漏洞代码审计 Skill

对 Go / Java / Python / PHP / JavaScript Web 项目进行系统化源码安全审计，输出可交付的审计报告 + 每条漏洞的并行验证报告（真实漏洞 PoC 或误判说明）。

---

## 核心约束（强制遵守）

1. **报告输出路径** = `{TARGET_PROJECT}/reports/`（被审计项目根目录，**不是** skill 仓库内）。主审计报告命名 `{project-name}-audit-{YYYY-MM-DD}.md`。
2. **只审计 High / Medium**。Low 漏洞**一律不写入报告**（即使发现也跳过）。
3. **审计报告必须含「项目文件树 + 审计标记」章节**：全部目录到文件，仅源码文件（`.go` / `.java` / `.kt` / `.scala` / `.py` / `.php` / `.js` / `.ts`）标记 `(审计)` / `(未审计)`，其他文件类型无标记。
4. **Phase 4 子 Agent 必须并行 spawn**：在单次响应中通过多个 `Agent` 工具调用并行启动（不是串行）。
5. **PoC 验证优先真实运行**：从被审计项目 README 提取 docker / docker-compose 启动指令，实际拉起环境并发送真实 HTTP 请求复现；失败再降级为静态代码证明，并在报告中显式标注「未运行验证，仅静态推理」。
6. **PoC / FP 报告命名**：真实漏洞 → `poc-V-{NNN}.md`；误判 → `fp-V-{NNN}.md`，与主审计报告共存于 `reports/`。
7. **Phase 3 主审计和 Phase 3.5 二次扫描必须遵守 Agent Contract**：包括工具约束（Grep/Glob/Read，禁 Bash grep/find/cat）、Turn 预留规则（max_turns - 3 时停止探索并产出输出）。详见下方「工具使用约束」章节。

---
## 工具使用约束（Agent Contract）

> 以下约束适用于 **Phase 3 主审计**、**Phase 3.5 二次扫描** 和 **Phase 4 子 Agent**。每条规则都是强制性的。

### 1. 工具约束

| 约束 | 详情 |
|------|------|
| **搜索** | 必须使用 Grep（ripgrep 模式，1-3 秒）定位，Glob 匹配文件名，Read 读文件 |
| **禁止写法** | **Bash 中的 grep / find / cat**（性能退化） |
| **超时** | Bash timeout ≤30s。Grep 超时 → 缩小 path → 连续失败 2 次 → 跳过 |

### 2. Turn 预留规则

```
Phase 3 主审计:
  max_turns = 30（根据项目规模调整：小项目 20，大项目 40）
  turns_used ≥ max_turns - 3 时：立即停止探索，产出结构化输出
  不得将最后 3 个 turn 用于新的 Grep/Read 探索

Phase 3.5 二次扫描:
  max_turns = 20（聚焦搜索，比对主审计少）
  turns_used ≥ max_turns - 3 时：立即停止搜索，产出结构化输出
  不得将最后 3 个 turn 用于新的 Grep/Read 探索

Phase 4 子 Agent:
  max_turns = 15（单漏洞验证，任务聚焦）
  turns_used ≥ max_turns - 3 时：立即停止验证，产出判定结果
```

违反 Turn 预留将导致输出丢失，整个 Agent 的发现可能被截断。
---

## 输入

用户提供（或采用默认）：
- `target_project`：被审计项目的根目录路径。**默认为当前工作目录**。
- 可选：`scope`（审计范围，如 `internal/`、`src/main/java/`），不指定则全量。

## 输出

写入到 `{target_project}/reports/`：
- `{project}-audit-{YYYY-MM-DD}.md` —— 主审计报告（漏洞清单 + 文件树 + 详细发现 + 验证汇总）
- `poc-V-{NNN}.md` —— 每个真实漏洞一份独立 PoC 报告
- `fp-V-{NNN}.md` —— 每个误判一份误判说明

---

## 执行流程

### Phase 0 — 输入解析

1. 解析 `target_project`（缺省 = `pwd`）
2. 创建输出目录：`mkdir -p {target}/reports/`
3. 记录审计起始时间，确定主报告文件名 `{project}-audit-{YYYY-MM-DD}.md`

### Phase 1 — 项目类型识别

读取 `references/project-detection.md` 的探测规则：

| 信号 | 判定 | 加载清单 |
|---|---|---|
| 根目录存在 `go.mod` | Go | `references/go-vuln-checklist.md` |
| 根目录存在 `pom.xml` / `build.gradle` / `build.gradle.kts` | Java | `references/java-vuln-checklist.md` |
| 根目录存在 `requirements.txt` / `setup.py` / `pyproject.toml` / `Pipfile` | Python | `references/python-vuln-checklist.md` |
| 根目录存在 `composer.json` | PHP | `references/php-vuln-checklist.md` |
| 根目录存在 `package.json`（且无 `go.mod` / `pom.xml`） | JavaScript/Node.js | `references/javascript-vuln-checklist.md` |
| 同时存在多种标记 | mixed | 对应清单都加载，按文件后缀路由 |
| 均不匹配 | abort | 终止并提示用户确认项目类型 |

附加：扫常见框架 import（Gin / Echo / Fiber / Spring Boot / JAX-RS / Servlet / Flask / Django / FastAPI / Laravel / Symfony / Express / Next.js），用于 Phase 2 建模时精准定位入口注册点。

### Phase 2 — 快速建模（10~30 分钟）

按已加载清单的 §3 执行：

1. **找入口**：路由注册点、`main`、Controller、Filter、Handler
2. **划信任边界**：HTTP 输入（query/body/header/path/cookie）、外部系统（DB/Redis/MQ/第三方 HTTP）、配置（env/文件/Secret）
3. **列高危 sink**：命令执行 / SQL / 文件 / 网络 / 模板 / 反序列化 / XXE
4. **生成项目文件树初版**：用 `find` 或 `ls -R` 列出全部目录到文件，源码文件后追加 `(未审计)` 占位（Phase 3 审计时改为 `(审计)`）

### Phase 3 — 主审计

按清单的 §4 分主题逐项扫描。**每发现一条 High / Medium 漏洞**：

1. 立即追加到主审计报告（用 `references/audit-report-template.md` 的格式）
2. 同步更新 §2.5 文件树章节：把对应源码文件的标记从 `(未审计)` 改为 `(审计)`
3. 漏洞编号 V-001、V-002、... 依次递增
4. **Low 漏洞跳过**：发现 Low 时记录在心里即可，不写入报告

主审计报告结构：
- §1 概览 + 风险结论（只有 High / Medium 计数）
- §2 发现列表（表格）
- §2.5 **项目文件树与审计覆盖**（全目录到文件，源码标审计状态）
- §3 详细发现（每条 V-XXX 含位置、证据、复现、修复、验证）
- §4 架构级风险与改进建议（可选）
- §5 验证结果（Phase 5 填充）

### Phase 3.5 — 同类漏洞二次寻找与系统性缺陷发现

> 前置条件：Phase 3 主审计已完成，主审计报告已初步生成（含 §1–§4）。
> 目的：当 Phase 3 发现某类漏洞的 1–2 个实例时，这可能指向系统性缺陷——
> 相同模式很可能在代码库的其他位置（特别是未审计文件）存在更多实例。
> Phase 3.5 执行一次"模式驱动"的全量搜索，发现被 Phase 3 遗漏的同源漏洞。

#### Step 3.5.1 — 分析 Phase 3 漏洞分布

1. 读取主审计报告 §2 发现列表，构建**漏洞类型分布表**：

```
| 漏洞类型 | 数量（Phase 3）| 涉及文件 | 涉及目录 |
|----------|---------------|---------|---------|
| SQL 注入  | 2             | ...     | ...     |
```

2. 对每种漏洞类型，提取 Phase 3 发现的**脆弱模式特征**：
   - 使用的 sink 函数/API（如 `db.Query(fmt.Sprintf(...))`、`exec.Command(...)`）
   - 参数来源模式（直接从 request 参数传递 vs. 经转换后传递）
   - 是否有防护措施及防护类型（参数化查询 / 转义函数 / 白名单）

#### Step 3.5.2 — 交叉引用 §2.5 文件树与审计覆盖

1. 读取报告 §2.5 文件树，识别 `(未审计)` 文件
2. 对每种漏洞类型，确定**重点搜索目录**：
   - **P0**：与已知漏洞文件同目录的 `(未审计)` 文件（同一模块更可能复用相同模式）
   - **P1**：包含同类 Sink 函数的所有 `(未审计)` 文件（全局 Grep 确定）
   - **P2**：包含同类 Sink 函数的所有文件（含已审计文件，查验是否有遗漏）

#### Step 3.5.3 — 同源漏洞二次搜索

对 Phase 3 发现的**每一种漏洞类型**，执行以下搜索过程：

```
对每种类型 T:
  1. 基于 Phase 3 的脆弱模式，构造通用搜索 pattern
     （从具体代码抽象为模式：Sink 函数名 + 变量参数特征）

  2. 用 Grep 在代码库全量搜索该 pattern

  3. 对每个新命中的候选:
     a. Read 上下文（±20 行）判断参数是否来自外部输入
     b. 追踪数据流: Source → Sink
     c. 验证无有效防护
     d. 若确认 → 记录为新的漏洞候选

  4. 对 Phase 3 已审计但未标记漏洞的文件，若 Step 3 Grep 命中 →
     也需要 Read 确认是否漏报。如确认漏报 → 追加。

  5. 每条确认的新漏洞，标记来源为 "Phase 3.5 二次发现"
```

**约束与限制**：

- **跳过规则**：若 Phase 3 已有 ≥5 个同类实例 → 跳过该类型（已饱和，无需二次搜索）
- **上限规则**：每种类型新发现的实例数上限 = 8（防止单一模式耗尽 turns）
- **合并规则**：同 pattern 在 ≥3 文件出现 → 合并报告，不逐个深挖每个文件
- **去重规则**：与 Phase 3 发现去重（同文件 + 同行号 + 同类型 = 重复，不追加）

#### Step 3.5.4 — 系统性缺陷判定

对每种漏洞类型 T，统计 Phase 3 + Phase 3.5 的合并实例数：

- `count(T) >= 3` → 标记为「系统性缺陷」
- `count(T) >= 5` → 标记为「严重系统性缺陷」

对系统性缺陷，生成分析条目：

```
[系统性缺陷] 类型: {T}
  实例数: {N} 个（关联 V-XXX, V-YYY, ...）
  影响范围: {目录/模块列表}
  根因分析: {为什么多处存在？是缺少统一防护函数？
             是代码规范缺失？是框架使用方式不当？}
  全局修复建议: {统一修复策略，非单点修补}
```

系统性缺陷条目将在 Step 3.5.5 中写入 §4 架构风险。

#### Step 3.5.5 — 更新审计报告

1. **§2 发现列表**：追加新发现，V-{N+1}, V-{N+2}, ... 接续 Phase 3 编号
2. **§3 详细发现**：追加子标题 `### Phase 3.5 二次发现（同源漏洞扫描）` + 新发现条目（使用与 Phase 3 相同的详细发现模板）
3. **§2.5 文件树**：将 Phase 3.5 新读过的文件从 `(未审计)` 改为 `(审计)`
4. **§4 架构风险**：系统性缺陷条目写入（如有）
5. **§1 概览**：更新计数以反映 Phase 3.5 新增的 High/Medium 数量

#### Agent Contract（Phase 3.5 专用）

```
max_turns = 20（聚焦搜索，比主审计少）
工具调用 ≤ 40 次，Bash ≤ 5 次
Turn 预留: turns_used ≥ max_turns - 3 时停止探索，产出输出
工具约束: Grep/Glob/Read，禁止 Bash grep/find/cat
Bash timeout ≤ 30s。Grep 超时 → 缩小 path → 连续失败 2 次 → 跳过

特殊约束:
  - 禁止对 Phase 3 已发现 ≥5 个实例的类型进行二次搜索
  - 同类型 ≥3 个新实例 → 停止该类型搜索（标记系统性缺陷候选，不再追加）
  - 搜索结果必须与 Phase 3 输出合并去重
```

**边界情况**：
- Phase 3 发现 **零漏洞** → 跳过 Phase 3.5，直接进入 Phase 4
- Phase 3.5 发现 **零新实例** → 记录 "Phase 3.5 完成：已搜索 {N} 种模式，覆盖 {M} 个文件，未发现新实例。Phase 3 对该类型覆盖充分。"
- Phase 3.5 发现 **≥5 新实例** → 对该类型触发上限，停止搜索，输出系统性缺陷

### Phase 4 — 并行漏洞验证

**关键：所有子 Agent 必须在同一次响应内并行 spawn**（多个 `Agent` 工具调用并列出现，不要串行）。

读取 Phase 3 + Phase 3.5 写出的主审计报告，对**每一条** High / Medium 漏洞 spawn 一个独立子 Agent（Phase 3 与 Phase 3.5 发现统一处理）：

子 Agent 输入 prompt 模板：
```
---Agent Contract---
1. 搜索路径: {主审计确定的源码目录}。排除: vendor, node_modules, .git, build, dist, test。
2. 必须使用 Grep/Glob/Read 工具。禁止 Bash 中 grep/find/cat。
3. 工具调用 ≤30 次，Bash ≤5 次。max_turns: 15。
   ★ Turn 预留: turns_used ≥ max_turns-3 时立即停止探索，产出结构化输出。
   不得将最后 3 个 turn 用于新的 Grep/Read 探索。
---End Contract---

你是一名安全验证 Agent，任务是验证以下漏洞的真实可利用性。

# 漏洞信息
- ID: V-XXX
- 标题: {title}
- 严重度: {High/Medium}
- 位置: {file:line}
- 复现思路: {从主报告 §3 复制}

# 被审计项目根目录
{target_project}

# 输出目录
{target_project}/reports/

# 任务步骤
1. 读取 {target_project}/skills/web-vuln-audit/references/validation-questions.md，按 Q-G1~Q-G5 + 漏洞类型专项追问逐项作答，每条答案必须带 file:line 证据
2. 尝试真实运行验证：
   a. 读 {target_project}/README.md，提取 docker / docker-compose / make / mvn / go run 启动指令
   b. 执行启动指令，等待服务就绪
   c. 按 Q 清单设计 PoC payload，发实际 HTTP 请求验证
   d. 启动失败或无 docker 配置 → 降级为静态推理，并在报告中显式标注「未运行验证，仅静态推理」
3. 综合判定 TP（真实漏洞）/ FP（误判）
4. 输出报告：
   - TP → 用 references/poc-report-template.md，写到 {target_project}/reports/poc-V-XXX.md
   - FP → 用 references/false-positive-template.md，写到 {target_project}/reports/fp-V-XXX.md
5. 验证完成后，返回一行 JSON：{"id": "V-XXX", "verdict": "TP|FP", "report": "poc-V-XXX.md|fp-V-XXX.md", "runtime_verified": true|false}
```

### Phase 5 — 汇总

收集所有子 Agent 返回的 JSON 结果，在主审计报告末尾追加 `## 5 验证结果` 表：

| ID | 标题 | 判定 | 是否运行验证 | 报告文件 |
|---|---|---|---|---|
| V-001 | SSRF - ... | TP | ✅ | [poc-V-001.md](poc-V-001.md) |
| V-002 | XSS - ... | FP | ❌（静态） | [fp-V-002.md](fp-V-002.md) |

---

## 引用文件

放在 `references/` 下，按需 Read：

| 文件 | 用途 |
|---|---|
| `project-detection.md` | Phase 1 项目类型识别规则 + 框架探测关键词 |
| `go-vuln-checklist.md` | Go 项目漏洞清单（9 大类 + sink 关键词 + 静态扫描工具） |
| `java-vuln-checklist.md` | Java 项目漏洞清单（12 大类 + sink 关键词 + 静态扫描工具） |
| `python-vuln-checklist.md` | Python 项目漏洞清单（sink 关键词 + 静态扫描工具） |
| `php-vuln-checklist.md` | PHP 项目漏洞清单（sink 关键词 + 静态扫描工具） |
| `javascript-vuln-checklist.md` | JavaScript/Node.js 项目漏洞清单（sink 关键词 + 静态扫描工具） |
| `audit-report-template.md` | 主审计报告模板（含 §2.5 文件树章节，去 Low） |
| `validation-questions.md` | Phase 4 子 Agent 的 Q1~Qn 质疑问题清单 + 判定规则 |
| `poc-report-template.md` | 真实漏洞 PoC 报告模板（项目描述 + 启动方式 + 利用步骤） |
| `false-positive-template.md` | 误判报告模板（Q 答复 + 误判原因） |
| `example-reports/go-example.md` | Go 项目示范报告（apache-answer，few-shot 参考） |
| `example-reports/java-example.md` | Java 项目示范报告（cordys-crm，few-shot 参考） |

---

## 严重度判定标准（去 Low 后的边界）

- **High**：可直接导致 RCE / 敏感数据泄露 / 越权访问 / SSRF 内网穿透 / 未授权管理操作
- **Medium**：需要特定前置条件（已登录用户、特定配置、特定时序），或影响面有限，但仍可造成实质危害
- **Low（跳过，不入报告）**：理论存在风险但难以利用，或仅降低纵深防御（如缺失安全响应头、可预测 ID）

存疑时：宁可记为 Medium 进入报告（Phase 4 会做可利用性验证），也不要直接当 Low 丢弃。

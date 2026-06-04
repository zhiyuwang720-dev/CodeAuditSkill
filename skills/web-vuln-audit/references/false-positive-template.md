# 误判验证报告模板（False Positive / FP）

> 当 Phase 4 子 Agent 判定漏洞为 **FP（误判）** 时使用本模板。
> 输出文件命名：`fp-V-{NNN}.md`，写入到 `{target_project}/reports/`。

---

# V-{NNN} 误判验证结果

## 漏洞信息

- **ID**：V-{NNN}
- **原标题**：
- **原判定严重度**：High / Medium
- **原报告位置**：`file:line`（主审计报告 §3.V-{NNN}）

## 判定结论

🟢 **误判（False Positive）**

## 误判原因

（**精炼总结**，3~5 行内说明为什么本次判定不构成真实漏洞。引用下方 Q 答复中的关键证据）

> 示例 1：sink 所在文件 `internal/dev/debug.go` 的 build tag 为 `//go:build dev`，仅在开发模式编译。生产 Dockerfile 用默认 tag 构建，该 handler 不会被注册到生产 HTTP server，路由不可达。
>
> 示例 2：看似拼接 SQL 的代码 `db.Exec("SELECT ... WHERE id=" + id)` 中，`id` 在上游被 `strconv.Atoi(id)` 校验并赋值为 `int` 类型；后续传入 `Sprintf` 时已不存在字符串注入可能。

---

## Q 清单逐项答复

> 参考 `references/validation-questions.md`，按通用 5 问 + 漏洞类型专项追问逐项作答。
> **每个答案必须带 `file:line` 证据**。

### 通用 5 问

#### Q-G1：用户可控的输入是否真的能到达 sink？

> 给出数据流证据或证否

#### Q-G2：用户输入是否被有效清理？

> 定位清理/校验代码，证明阻断有效

#### Q-G3：代码是否处于测试 / 演示 / 死代码 / 自动生成上下文？

> 检查 build tag、文件路径、是否被注册到生产路由

#### Q-G4：漏洞触发是否需要前置条件？

> 列出前置条件，并说明现实可达性

#### Q-G5：是只能理论上存在威胁，还是可复现可利用？

> 综合判断可利用性等级

### 漏洞类型专项追问

（按漏洞主类型填写对应 Q-X 组，例如命令注入对应 Q-C1~Q-C4）

---

## 真实运行验证（如执行）

（若尝试拉起 docker 环境并测试 PoC，记录测试过程；若未运行，标注「仅静态分析」）

```bash
# 若运行了 PoC 但未触发，记录失败的请求
$ curl -i 'http://127.0.0.1:8080/api/...' -d '...'
HTTP/1.1 400 Bad Request
{"error":"invalid input"}
# → 输入被框架层 binding 拒绝
```

---

## 建议

- **是否需要从原审计报告中移除**：是 / 否
- **是否更新审计规则减少同类误判**：若是，说明可加入清单的反向模式（例如「检测到 `strconv.Atoi` 前置校验时降级判定」）
- **是否仍存在纵深防御考虑**：（虽不构成可利用漏洞，但代码可读性 / 健壮性建议）

---

## 关联信息

- 对应主审计报告：`{project}-audit-{YYYY-MM-DD}.md` 的 `V-{NNN}` 条目
- 验证 Agent ID：
- 验证时间：（YYYY-MM-DD HH:MM:SS）

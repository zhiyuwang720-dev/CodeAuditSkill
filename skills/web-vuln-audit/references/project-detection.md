# 项目类型识别规则

Phase 1 使用本规则识别被审计项目语言，选择正确的漏洞清单。

---

## 1. 主要判定信号（按优先级）

在 `target_project` 根目录执行检测：

| 探测命令 | 命中文件 | 判定 | 加载清单 |
|---|---|---|---|
| `test -f {target}/go.mod` | `go.mod` | **Go** | `references/go-vuln-checklist.md` |
| `test -f {target}/pom.xml` | `pom.xml`（Maven） | **Java** | `references/java-vuln-checklist.md` |
| `test -f {target}/build.gradle` | `build.gradle`（Gradle Groovy DSL） | **Java** | `references/java-vuln-checklist.md` |
| `test -f {target}/build.gradle.kts` | `build.gradle.kts`（Gradle Kotlin DSL） | **Java** | `references/java-vuln-checklist.md` |
| `test -f {target}/settings.gradle` 或 `settings.gradle.kts` | （辅助证据，存在 Gradle 项目结构） | Java | 同上 |

### 复合情况

| 命中组合 | 判定 | 处理方式 |
|---|---|---|
| 仅 Go 信号 | Go | 单语言审计 |
| 仅 Java 信号 | Java | 单语言审计 |
| Go + Java 信号都有 | **mixed** | 两份清单都加载，按文件后缀路由：`.go` 走 Go 清单，`.java/.kt/.scala` 走 Java 清单 |
| 均无 | **abort** | 终止 skill，提示「当前 skill 仅支持 Go / Java Web 项目，请确认项目类型」 |

---

## 2. 框架与技术栈识别（辅助 Phase 2 建模）

识别到语言后，进一步扫常见 import / 配置，用于精准定位入口。

### 2.1 Go Web 框架

| 框架 | 探测信号（grep import 路径） |
|---|---|
| 标准库 net/http | `"net/http"` + `http.HandleFunc` / `http.Handle` / `http.ListenAndServe` |
| Gin | `github.com/gin-gonic/gin` + `gin.Engine` / `gin.Default()` |
| Echo | `github.com/labstack/echo` + `echo.New()` |
| Fiber | `github.com/gofiber/fiber` + `fiber.New()` |
| Chi | `github.com/go-chi/chi` + `chi.NewRouter()` |
| Beego | `github.com/beego/beego` |
| Gorilla Mux | `github.com/gorilla/mux` |

### 2.2 Java Web 框架

| 框架 | 探测信号 |
|---|---|
| Spring Boot | `pom.xml` 含 `spring-boot-starter-web` 或 `@SpringBootApplication` |
| Spring MVC | `@RestController` / `@Controller` + `@RequestMapping` |
| Spring WebFlux | `spring-boot-starter-webflux` 或 `@RestController` 返回 `Mono`/`Flux` |
| Servlet | `javax.servlet.http.HttpServlet` 或 `jakarta.servlet.http.HttpServlet` |
| JAX-RS | `javax.ws.rs.Path` 或 `jakarta.ws.rs.Path` |
| Struts2（历史） | `pom.xml` 含 `struts2-core` |

### 2.3 常见配置文件（用于辅助建模与暴露面检查）

- **Go**：`config.yaml` / `config.toml` / 环境变量 / `Dockerfile` / `docker-compose.yml`
- **Java**：`application.yml` / `application.properties` / `bootstrap.yml` / `Dockerfile` / `pom.xml` 中的 dependency

---

## 3. 探测脚本示例（供 Phase 1 使用）

```bash
# Phase 1 一键检测
cd "$TARGET_PROJECT" || exit 1

HAS_GO=$( [ -f go.mod ] && echo 1 || echo 0 )
HAS_JAVA=$( ( [ -f pom.xml ] || [ -f build.gradle ] || [ -f build.gradle.kts ] ) && echo 1 || echo 0 )

if [ "$HAS_GO" = "1" ] && [ "$HAS_JAVA" = "1" ]; then
    echo "lang=mixed"
elif [ "$HAS_GO" = "1" ]; then
    echo "lang=go"
elif [ "$HAS_JAVA" = "1" ]; then
    echo "lang=java"
else
    echo "lang=unknown" >&2
    exit 2
fi
```

---

## 4. 边界处理

- **monorepo / 多模块**：先在根目录检测，若顶层无 `go.mod`/`pom.xml`，向下递归一层探测子目录。如果发现多个独立模块，每个模块各跑一遍主流程，输出到各自的 `reports/`。
- **空仓库 / 仅 README**：abort，提示用户提供有效源码目录。
- **生成代码混杂**（如 `protobuf` 生成的 `*.pb.go`）：在 Phase 2 建模阶段过滤掉，文件树仍保留但不计入「需审计」。

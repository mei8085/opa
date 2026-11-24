# 策略能力清单（Capabilities）收敛后的生效边界

- 代码版本：OPA `1.23.0-dev`，commit `6824432`（工作区基线即该提交）
- 分析方式：通读 parse → compile → eval → rego 门面 → server/bundle/wasm 实际链路，并用 `go1.26.11` 在本环境实跑验证（离线 `GOPROXY=off`）
- 结论标记：
  - **【源码】**：直接来自当前检出的源码，附 `文件:行`
  - **【实测】**：除源码外，还在本环境写程序 / 构建 OPA 二进制实际运行确认
  - **【待验证】**：本仓库内无法定论，必须在目标部署 / 准入集成中验证

---

## 0. 一句话结论

`Capabilities.Builtins` 白名单的**强制点是“编译期符号解析 + 类型检查”，不是求值期沙箱**。把名单收敛后，任何调用名单外函数的策略 / 查询，在标准 `ast.Compiler` → `rego` → `bundle.Activate` 链路都会得到 `rego_type_error: undefined function <name>`，此时 `Compiler.Failed()==true`、`rego.Eval` 返回 Go `error`、OPA Server 上传接口返回 `400`、bundle 激活返回错误。它**不会**产出一个 allow/deny 结果，因此只要上游正确处理“编译 / 激活 / 求值错误”，不支持的规则在 OPA 内部就不可能悄然变成一个正常准入决定。**【源码】【实测】**

但“白名单收敛”并不自动等于“运行中的准入服务只允许这些内置功能”，有三个必须堵上的缝隙（详见 §5、§6）：

1. **原生 `opa run` / Go SDK / config 根本没有暴露 capabilities 配置**，服务端编译器默认使用全量 **207** 个内置函数；CI 里的 `opa check --capabilities` 不会约束正在运行的 Server。**【源码】【实测】**
2. **准入 Webhook 如何对待 OPA 错误 / 空结果在本仓库之外**；若吞掉激活错误、用空编译器评估、或把空 `deny` 当放行，就会“悄然准入”。这是头号 **【待验证】** 项。
3. **绕过 AST 编译门禁的路径在求值期不复查白名单**：注入自带 `Compiler` 时 `rego.Capabilities(...)` 不会应用到它；直接喂 AST 给 `topdown`、注册自定义 builtin、运行预编译 wasm/bundle 都可越过名单——实测空名单编译器下 `concat`、`regex.match` 仍被求值执行。**【源码】【实测】**

此外要区分一个**不同层面**的静默语义：名单**内**的 builtin 在求值时“运行出错”，默认非 strict 模式会让该表达式变 undefined 并丢弃错误，可能使 `deny` 集合为空，HTTP `200 {"result":[]}`。这不是“能力不支持”（能力缺失在编译期就失败），但同样会改变准入结果，准入数据调用应显式 `strict-builtin-errors` 或收集 `BuiltinErrorList` 并 fail-closed。**【源码】【实测】**

---

## 1. 能力清单是什么

`ast.Capabilities` 定义于 `v1/ast/capabilities.go:104`：

```go
type Capabilities struct {
    Builtins        []*Builtin       // 允许的内置函数白名单（按名字匹配）
    FutureKeywords  []string
    WasmABIVersions []WasmABIVersion
    Features        []string         // rego_v1 / rego_v2 / rule_head_refs ...
    AllowNet        []string         // 唯一会进入求值期的“能力”，管网络出口
}
```

- `CapabilitiesForThisVersion()` 直接用全量 `ast.Builtins` 填充 `Builtins`（`v1/ast/capabilities.go:170-191`）。**【源码】**
- 实测本版本 `len(CapabilitiesForThisVersion().Builtins) == len(ast.Builtins) == 207`。**【实测】**
- `ContainsBuiltin` 仅按 `Name` 线性匹配（`v1/ast/capabilities.go:297-301`）。全仓搜索 `ContainsBuiltin` 的非测试调用方，AST 外为 **0**；AST 内除定义外只有模板字符串特性门禁一处（`v1/ast/compile.go:2882-2883`）。**【源码】**

> 关键含义：全仓没有任何“求值前再问一次 `capabilities.ContainsBuiltin(name)`”的运行时关卡。

---

## 2. 实际链路逐层分析

### 2.1 Parse 阶段：只卡语法 / 语言特性，不认识内置函数名

- Parser 仅在 `Capabilities == nil` 时补一份当前版本全量清单（`v1/ast/parser.go:308-310`）。
- 清单在 parse 期只用于：
  - Rego v1/v2 所需的 `rego_v1`/`rego_v2` feature，缺失直接 `rego_parse_error: illegal capabilities: ... feature required for parsing ... Rego`（`v1/ast/parser.go:314-323`）；
  - 允许的 future keywords 白名单与 “unknown keyword” 报错（`v1/ast/parser.go:332-358`）。
- **内置函数在语法上只是一个 ref 调用，parser 不校验它是否在 `Builtins` 名单内。**

实测：默认 parser 选项解析含 `regex.match(...)` 的模块返回 `err=<nil>`；而给一份连 `rego_v1` feature 都没有的空清单去解析 v1 语法 / 或作为查询 parser 选项时，会得到上面的 feature 报错。**【实测】**

### 2.2 Compile 阶段：白名单真正生效的强制点

编译器在类型检查环境构建“本编译器认识的 builtin 表”，来源**只有**能力清单 + 自定义 builtin（`v1/ast/compile.go:1048-1061`）：

```go
if c.capabilities == nil {
    c.capabilities = CapabilitiesForThisVersion()   // 不传 = 全量
}
c.builtins = make(map[string]*Builtin, ...)
for _, bi := range c.capabilities.Builtins {
    c.builtins[bi.Name] = bi                        // 白名单逐项入表
}
maps.Copy(c.builtins, c.customBuiltins)             // 自定义 builtin 无条件叠加
c.TypeEnv = checker.Env(c.builtins)
```

函数 arity 解析 `GetArity` 先查这张表，再查用户规则，都没有才返回 `-1`（`v1/ast/compile.go:738-747`）：

```go
if bi := c.builtins[ref.String()]; bi != nil { return bi.Decl.Arity() }
rules := c.GetRulesExact(ref)
if len(rules) == 0 { return -1 }
```

默认编译阶段里固定包含 `StageCheckUndefinedFuncs`（`v1/ast/compile.go:488`），它遍历**所有模块的所有表达式**（与规则是否可达无关），对 `arity < 0` 的调用产出（`v1/ast/compile.go:1894-1896`）：

```go
errs = append(errs, NewError(TypeErr, expr.Loc(),
    "undefined function %v", ref))     // code = rego_type_error
```

即：**名单外函数 → `rego_type_error: undefined function ...` → `Compiler.Failed()==true`。** 即便是不可达规则里的调用也会被扫到，不存在“没被评估所以漏检”。**【源码】**

即席查询也有同名阶段（`v1/ast/compile.go:4255`，实现 `:4399-4404`），走的是同一个 `checkUndefinedFuncs`。**【源码】**

实测（Go 程序直接调 `ast.NewCompiler().WithCapabilities(...)`）：**【实测】**

| 能力清单 | 策略 | 结果 |
|---|---|---|
| `builtins: []`（且无 feature） | `allow if { true }` | 编译通过 |
| `builtins: []` | `allow if { 1 == 1 }` | `rego_type_error: undefined function equal` |
| `builtins: []` | 调 `regex.match` | `undefined function regex.match` |
| 全量去掉 `regex.match`（206 项） | 调 `regex.match` | `undefined function regex.match` |
| 同上 206 项 | 调 `concat` | 编译通过 |

> 实操提醒：**不要直接从 `{"builtins":[]}` 起步**。`equal`/`eq`/`assign` 等核心操作符本身也是声明式 builtin，会被一起删掉。用 `CapabilitiesForThisVersion()` 做减法，或基于官方 `capabilities/v*.json` 裁剪，并保留 `features: ["rego_v1", ...]`，再用真实策略集跑 `opa check --capabilities` 校准。

CLI 实测（本环境构建的 `opa v1.23.0-dev`）：空 `builtins` + `rego_v1` feature 的 caps 文件下，`opa check --capabilities=empty-caps.json deny.rego` 报 `undefined function regex.match` 与 `undefined function eq`，退出码 `1`；不带 `--capabilities` 时退出码 `0`；纯 `allow if { true }` 在空名单下退出码 `0`。**【实测】**

### 2.3 求值阶段（topdown）：按全局注册表分发，不按白名单放行

求值分发函数 `builtinFunc` 查的是**全局** `ast.BuiltinMap`、**全局** `builtinFunctions` 注册表以及本次 query 的自定义 builtin（`v1/topdown/eval.go:192-207`），全程不读 `Capabilities.Builtins`：

```go
decl, ok := ast.BuiltinMap[name]       // 全局全量声明
if ok {
    if f, ok := builtinFunctions[name]; ok { return decl, f, true } // 全局实现
    if bi, ok := e.builtins[name]; ok { ... }
}
if bi, ok := e.builtins[name]; ok { ... }
return nil, nil, false
```

全局实现在 `init()` 经 `RegisterBuiltinFunc` 注册（`v1/topdown/builtins.go:89-125`）。真找不到时返回的是 `unsupportedBuiltinErr`，code 为 `eval_internal_error` / `internal_err` 类的**硬错误**，不是 undefined 决定（调用点 `v1/topdown/eval.go:1186-1189`；定义 `v1/topdown/errors.go:158-164`）。**【源码】**

`Capabilities` 在求值期确实被放进 `BuiltinContext`（`v1/topdown/eval.go:1208-1235`，字段定义 `v1/topdown/builtins.go:59`），但全 topdown 对它的**实际使用只有 `AllowNet` 网络出口校验**：

- `v1/topdown/net.go:27` → `verifyHost(bctx.Capabilities, name)`
- `v1/topdown/http.go:402-409`（`verifyHost`/`verifyURLHost`），并在 `:475`、`:648` 对 URL 生效
- `v1/topdown/jsonschema.go:69-70` 把 `AllowNet` 赋给 schema loader

`AllowNet` 语义（`v1/ast/capabilities.go:114-120`）：省略 = 任意主机；空数组 = 禁止任何主机。**【源码】**

**绕过编译直接求值的实测**：构造一个带“空 builtin 名单”、从未 `Compile()` 过的 `ast.Compiler`，用 `topdown.NewQuery(body).WithCompiler(它)...Run(ctx)` 直喂未编译 AST：**【实测】**

- `concat(",", ["a","b"], x)` → 成功，`x = "a,b"`（1 行结果）
- `regex.match("^e","evil")` → 成功匹配（1 行结果）

这彻底说明：**capabilities 不是求值沙箱**。正常路径之所以安全，仅仅是因为策略先过了 §2.2 的编译门禁。

### 2.4 rego 门面：错误以 Go `error` 返回，与 `ResultSet` 分离

- `Eval` 调 `PrepareForEval`，后者出错时直接 `return nil, err`（`v1/rego/rego.go:1572-1576`）。
- 模块 / bundle 编译统一走 `bundle.Activate`，失败被包成 `bundle activation failed: ...` 返回（`v1/rego/rego.go:2237-2252`）。
- 查询 parser 也会带上 `r.capabilities`（`v1/rego/rego.go:2211`）。

实测 `rego.New(rego.ParsedModule(m), rego.Capabilities(minusCaps)).Eval(ctx)`，其中策略调用被删的 `regex.match`：`rs=[]`、`err != nil`，错误文本 `bundle activation failed: ... rego_type_error: undefined function regex.match`。作为对照，正常授权结果 `allow=false` 返回 `[{[false]}]` 且 `err=<nil>`，命中的 `deny` 集合返回 `[{[[not-admin]]}]` 且 `err=<nil>`。**【实测】**

**注入编译器的坑（实测确认）**：只有当调用方**没有**注入 `rego.Compiler` 时，rego 才会 `ast.NewCompiler().WithCapabilities(r.capabilities)...`（`v1/rego/rego.go:1494-1505`，关键守卫 `if r.compiler == nil`）。若用了 `rego.Compiler(c)`，`rego.Capabilities(...)` **不会**再作用于 `c`。实测：向 rego 注入一个**全量且已编译成功**的 compiler，同时传更窄的 `rego.Capabilities(minus)`，调用 `regex.match` 的策略照常求值并返回 `blocked-by-regex`，`err=<nil>`。**【源码】【实测】**

> 因此“我在 `rego.New` 里设了 `Capabilities`”与“实际评估用的编译器受名单约束”不能划等号；注入 compiler 时必须自己对 `c` 调 `WithCapabilities(...)` 并重新编译。

### 2.5 自定义 builtin：在白名单之外无条件叠加

- 编译表构建时 `maps.Copy(c.builtins, c.customBuiltins)`（`v1/ast/compile.go:1059`）。
- rego 的 `rego.Function1/...`、`rego.Builtin...` 既加声明也加实现（最终 `WithBuiltins(r.builtinDecls)`，`v1/rego/rego.go:1498`；求值实现 `:2367` 一带）。
- 另外 `topdown.RegisterBuiltinFunc` 是进程级全局注册（`v1/topdown/builtins.go:89-91`）。

所以**实际生效集合 = `Capabilities.Builtins` ∪ 编译器 customBuiltins ∪ query 级 builtins ∪ 全局注册表中可被解析到的实现**。名单收敛只收敛了第一部分。目标二进制是否注册了额外强功能 builtin，**【源码】机制已确认，实际注册内容【待验证】**。

### 2.6 unsafe builtins：另一套“黑名单”，不要与 capabilities 混淆

- `Compiler.WithUnsafeBuiltins` / `rego.UnsafeBuiltins` 对应默认阶段 `StageCheckUnsafeBuiltins`（`v1/ast/compile.go:496`，实现 `:2336-2343`；查询阶段 `:4259`、`:4430-4431`），报错 `rego_type_error: unsafe built-in function calls in expression: <name>`。源码注释标注 deprecated，建议用 capabilities。**【源码】**
- OPA Server 有一个包级硬编码名单 `unsafeBuiltinsMap = {ast.HTTPSend.Name: {}}`（`v1/server/server.go:101`），用于 `/v1/query`、`/v1/compile`、Data 构造 rego 三处（`:934`、`:1437`、`:2644`）。

但实测其作用域需要精确理解，**它不限制“已存储策略内部”的调用**：**【实测】**

- 即席查询 `/v1/query?q=http.send(...)` → `400 rego_type_error: unsafe built-in function calls ... http.send`。
- 但通过 `PUT /v1/policies/hs` 上传内部调用 `http.send` 的策略 → `200`（上传校验用的是新建的、**未**设 unsafe 名单的 `ast.NewCompiler()`，`v1/server/server.go:2271-2283`）。
- 再 `POST /v1/data/hs/deny?strict-builtin-errors=true` → 实际发起了网络调用并在连 `127.0.0.1:1` 被拒后返回 `500 / eval_builtin_error: http.send ... dial tcp ... connect: connection refused`；默认非 strict 时 → `200 {"result":[]}`。

原因：Server 用 `rego.Compiler(s.getCompiler())` 注入共享编译器（`v1/server/server.go` `makeRego` 约 `:2634`），因此 rego 不会在 `:1497` 对该编译器应用 unsafe 名单；`:2332` 的 unsafe 检查只作用于“由 URL 路径生成的查询本身”（一个 data ref，不含函数调用），不会递归检查已编译模块体。**【源码】**

### 2.7 Server / SDK / CLI：谁能真正装载收敛名单

- **`opa run` 没有 `--capabilities` 标志**（`cmd/run.go` 中无任何 capabilities 引用；`opa run --help | grep capab` 实测为空）。**【源码】【实测】**
- capabilities 标志由 `cmd/flags.go:138-139` 的 `addCapabilitiesFlag` 提供，实际用于 `check`（`cmd/check.go:58-59`）、`eval`（`cmd/eval.go:932-933`）、`build`（`cmd/build.go:349` 的 `.WithCapabilities(...)`）、`fmt`、`test` 等“构建 / 左移”命令。**【源码】**
- Server 上传策略的校验编译器是裸 `ast.NewCompiler().SetErrorLimit(...).WithPathConflictsCheck(...).WithEnablePrintStatements(...)`，**没有** `WithCapabilities`（`v1/server/server.go:2271-2274`）。
- 服务期评估统一注入 `s.manager.GetCompiler()`（`v1/server/server.go:2616-2618`；`v1/plugins/plugins.go:779-783`），全仓 `v1/sdk/**` 非测试代码**没有** `Capabilities` 字段，`config/`、`v1/config/` 也没有 capabilities 配置键。**【源码】**

结论：**原生常驻 OPA（含 Go 高级 SDK / 配置文件）没有提供“在服务编译器上收敛 builtin 白名单”的一等入口**。受限执行环境若要在运行期强制，必须：(a) 用更底层 `rego`/`ast` 自行装配并对 compiler 调 `WithCapabilities`；或 (b) 依赖 CI/`opa build` 期用名单门禁 + 只分发经审核的产物；或 (c) 自行 fork/扩展 server。目标环境到底采用了哪种，**【待验证】**（本仓库无法看出部署装配）。

### 2.8 Bundle 激活：编译错误在提交前返回

`bundle.Activate` 分派到具体 activator（`v1/bundle/store.go:386-405`）。默认流程在同一存储事务里合并“编译器已有模块 + extra + bundle 模块”，然后（`v1/bundle/store.go:1046-1048`）：

```go
if compiler.Compile(modules); compiler.Failed() {
    return compiler.Errors     // 尚未 commit；上层 abort 事务
}
```

即编译失败会在提交前返回错误，激活不生效。rego 门面据此返回 `bundle activation failed`（见 §2.4，已实测）。**【源码】** 编译器由 `Manager` 在读锁后替换（`v1/plugins/plugins.go:779-789`），成功激活后才会换到新 compiler。**【源码】**

但“失败后是继续服务 last-good 编译器、空编译器，还是 readiness 失败 / 阻止发布”，取决于 bundle 插件配置、健康探针与发布流水线，**【待验证】**（见 §6）。

### 2.9 WASM / 预编译产物：名单是构建期概念，运行时只传 `AllowNet`

- `opa build --capabilities ... -t wasm` 在 AST/编译期受同一套 capabilities 约束（`cmd/build.go:349`）。**【源码】**
- wasm 运行时 `internal/wasm/sdk/opa/opa.go:171,192` 与 `internal/wasm/sdk/internal/wasm/vm.go`、`bindings.go:77-100` 确实透传 `Capabilities`，但和 topdown 一样是放进 builtin context 供 `AllowNet` 使用，没有 `ContainsBuiltin` 放行检查（全仓 grep 佐证）。**【源码】**
- wasm 内调用的 builtin 在构建时已解析为链接项 / host function；一份**已经构建好的** wasm/bundle 在加载执行时不会再用某份 `capabilities.json` 重新做 AST 符号检查。其 host function 具体集合、是否所有 Go builtin 都有 wasm 对应实现，需要按产物与 OPA 版本另行确认。**【待验证】**

---

## 3. HTTP 层“编译错误 / 正常决定 / 运行时错误”的实测对照

用本环境构建的原生 `opa run --server` 实测（默认全量能力）：**【实测】**

| 操作 | HTTP / 结果 | 类别 |
|---|---|---|
| `PUT` 使用 `regex.match` 的策略 | `200 {}` | 上传成功（全量名单） |
| `PUT` 使用 `http.send` 的策略 | `200 {}` | 上传成功（上传编译器无 unsafe 名单） |
| `PUT` 使用 `totally.nonexistent.fn` 的策略 | `400 invalid_parameter`，`code=rego_type_error`，`undefined function totally.nonexistent.fn` | **编译错误** |
| `POST /v1/data/admission/deny`，`name=evil-box` | `200 {"result":["bad"]}` | 正常拒绝（有 deny） |
| 同接口，`name=good` | `200 {"result":[]}` | 正常“无 deny” |
| 策略内 `json.unmarshal("!!!")` 运行出错，默认 | `200 {"result":[]}` | **错误被静默，deny 为空** |
| 同上 `?strict-builtin-errors=true` | 响应体 `code=internal_error`，内层 `eval_builtin_error ... invalid character`；源码 `makeRego` 注释明确评估错误以 **500** 返回（`v1/server/server.go` 约 `:2639-2645`），同类 strict 的 `http.send` 实测为 **HTTP 500** | 求值错误（显式） |
| `/v1/query?q=http.send(...)` | `400`，`rego_type_error: unsafe built-in function calls ... http.send` | 查询编译错误 |

库层面的对应实测：默认配置求值 `x := json.unmarshal("!!!not json")` → `rs=[] err=<nil>`；`rego.StrictBuiltinErrors(true)` → 返回 `eval_builtin_error`；`rego.BuiltinErrorList(&errs)` → 返回 `err=<nil>` 但收集到 1 个 `eval_builtin_error`。开关定义见 `v1/rego/rego.go:1344-1347` 与 `:1361-1365`，注入 topdown 选项在 `:2375-2377`。**【源码】【实测】**

机制源码：非 `Halt` 的 builtin 错误被追加到 `e.builtinErrors.errs` 后把局部 `err` 置 `nil`（`v1/topdown/eval.go:2458-2472`）；在 `Query.Run`/`PartialRun` 收尾时，只有 `strictBuiltinErrors==true` 才把第一个错误作为返回错误，否则只有显式提供 `builtinErrorList` 时导出，再否则丢弃（`v1/topdown/query.go:513-532` 与 `:630-649`）。**【源码】**

---

## 4. 生效边界总表

| 维度 | Capabilities.Builtins 是否生效 | 强制位置 / 证据 | 验证状态 |
|---|---|---|---|
| Parser 识别函数名 | 否（函数是普通 ref） | `v1/ast/parser.go` | 源码 + 实测 |
| Parser 语言特性 / 关键字 | 是（`Features`/`FutureKeywords`） | `parser.go:314-358` | 源码 + 实测 |
| **模块编译符号解析** | **是，主强制点** | `compile.go:738-747,1894-1896` | 源码 + 实测 |
| **即席查询编译** | **是** | `compile.go:4255,4399-4404` | 源码 |
| `opa check/build/eval --capabilities` | 是（构建 / 左移期） | `cmd/check.go:58`、`cmd/build.go:349` | 源码 + CLI 实测 check |
| rego 门面（自建 compiler） | 是 | `rego.go:1494-1505` | 源码 + 实测 |
| rego 门面 + 注入 `rego.Compiler` | **否（选项不再应用）** | `rego.go:1492-1515` | 源码 + 实测 |
| bundle 激活 | 取决于传入的 `Compiler` 是否带名单；失败在 commit 前返回 | `bundle/store.go:1046-1048` | 源码 +（rego 包装）实测 |
| topdown 求值分发 | **否**，只认全局 / query 注册表 | `eval.go:192-207` | 源码 + 实测 |
| 直喂 topdown AST | **否（可越名单执行）** | 同上 | 实测 |
| 自定义 builtin | **在名单外叠加** | `compile.go:1059` | 源码（实际注册内容待验证） |
| `AllowNet` 网络出口 | 是，且是唯一进入求值期的 caps 字段 | `net.go:27`、`http.go:402`、`jsonschema.go:69` | 源码（未做网络绕过实测） |
| 原生 `opa run` Server | **无 capabilities 入口，默认全量** | `cmd/run.go` 无该标志；`server.go:2271` | 源码 + 实测 help/上传 |
| Go 高级 SDK / config | 未发现 capabilities 字段 | `v1/sdk`、`config` grep | 源码（ManagerOpts 扩展空间待验证） |
| Server 对临时查询的 http.send | 由独立 unsafe 黑名单拦截 | `server.go:101,934` | 源码 + 实测 |
| Server 对已存储策略内 http.send | 不被该黑名单拦截（会真实执行） | `server.go:2271` + `rego.go:2332` 作用域 | 源码 + 实测 |
| WASM 运行时 | Builtins 白名单不复查；仅透传 `AllowNet` | `internal/wasm/.../opa.go:192`、`bindings.go` | 源码（host 函数集合待验证） |

---

## 5. 与“准入决定”的关系：三类结果绝不能混

一个准入路径上必须区分三种性质完全不同的返回：

1. **编译 / 能力错误（control-plane failure）**：名单外函数、语法 / 特性不支持、bundle 激活失败。OPA 侧表现为 `ast.Errors` / `Compiler.Failed()`、Go `error`、Server `400 rego_type_error`、bundle 激活错误。**它不是 allow，也不是 deny，而是“策略不可用”。** 正确做法是阻止该策略发布 / 加载，并在准入链路上 fail-closed。**【源码】【实测】**

2. **正常授权决定（data-plane decision）**：编译通过、求值无错，`allow=false`、`deny=[...]` 或 `deny=[]`。这些是策略逻辑结果，`err=nil`、HTTP 200。空 `deny` 的语义必须由策略 / Webhook 显式定义（通常空 deny = 允许）。**【源码】【实测】**

3. **求值期内置函数运行错误（另一种 data-plane 异常）**：函数在名单内、编译通过，但入参 / 网络等导致运行错误。默认非 strict 下它会退化为 undefined，可能得到 `200 {"result":[]}`——外观与第 2 类“正常空 deny”完全相同。准入数据调用应使用 `?strict-builtin-errors=true`（或 `rego.StrictBuiltinErrors` / `BuiltinErrorList`）把它提升为错误并 fail-closed。**【源码】【实测】**

> 核心安全断言：**“使用了名单外功能”在标准链路里属于第 1 类，不会自己变成第 2 类。** 它之所以可能“悄然变成准入决定”，只可能是因为外围把第 1 类（或第 3 类）错误吞掉后，拿空 / 旧编译器或空结果继续做了准入判断。OPA 仓库本身不包含 Kubernetes 准入 Webhook，故这最后一跳 **【待验证】**。

---

## 6. 源码已确认 vs 仍需验证

### 6.1 来自源码、且多数已在本环境实测的结论

- capabilities 的数据结构、默认全量 207 项、按名匹配（§1）。
- parse 期只管特性 / 关键字，不管函数名（§2.1）。
- 编译期 `c.builtins` 仅来自 caps + custom，`GetArity` 与 `checkUndefinedFuncs` 必然对名单外调用报 `undefined function`，模块与查询皆然，且扫描全模块（§2.2）。
- rego / bundle 的错误传播路径与 “bundle activation failed”（§2.4、§2.8）。
- topdown 求值按全局注册表分发、不复查 `ContainsBuiltin`；caps 在求值期仅用于 `AllowNet`（§2.3）。
- 注入 compiler 时 `rego.Capabilities` 不被应用；自定义 builtin 无条件叠加（§2.4、§2.5）。
- 运行时 builtin 错误默认被吞、表达式变 undefined；strict / errorList 才外露（§3）。
- 原生 `opa run` 与高级 SDK/config 无 capabilities 入口；上传校验用裸全量编译器（§2.7）。
- server 的 `{http.send}` unsafe 名单只管临时查询 / compile，不管已存储策略函数体（§2.6）。
- bundle 编译错误在事务提交前返回（§2.8）。

### 6.2 仅来自源码、尚未动态验证

- `AllowNet` 的实际网络拦截 / 绕过面（DNS、重定向等）只读到 `verifyHost`/`verifyURLHost` 调用点，未做网络实验。
- WASM 产物里 builtin → host function 的完整链接集合，以及特定 builtin 在 wasm target 是否可用。
- 高级 SDK 通过 `ManagerOpts` 注入受 caps 约束编译器的可行程度（`setCompiler` 为包内私有，需另找公开扩展点或自建装配）。

### 6.3 必须在目标部署 / 准入集成中验证（本仓库无法定论）

1. **部署到底如何装配 OPA**：是否真的把同一份收敛 caps 应用到了**服务 / SDK 的在用编译器**，而不是只在 CI 跑了 `opa check`。检查启动封装、是否注入自定义 `Compiler`、是否 `rego.Function*` / `topdown.RegisterBuiltinFunc` 注册了额外 builtin。
2. **Kubernetes / Gatekeeper / kube-mgmt / 自研 Webhook 的错误处理**：
   - 对 OPA 的非 200、错误体、超时、连接失败分别返回 `allowed: true` 还是 `false`；
   - Webhook 的 `failurePolicy: Fail/Ignore`、`timeoutSeconds`、`namespaceSelector`；
   - 是否把 “OPA 不可达 / 策略编译失败 / 结果缺字段” 与 “`deny: []`” 区分开；
   - 是否存在“激活失败但仍用空编译器对外服务 → 所有 data 文档为空 → 全放行”的窗口。
3. **Bundle / 策略发布与健康探针**：激活失败后是 last-good 继续服务还是空策略；readiness/liveness 是否能拦住坏版本滚动；回滚与多副本一致性。源码只保证事务内 `Compile` 失败不提交，运维行为需实测。
4. **预编译产物供应链**：是否分发 `opa build` 产物（含 wasm），构建时用的 caps 是否与声明的名单一致；运行时是否还会从源码重编译。
5. **名单内容本身的安全性**：收敛名单不等于最小权限。若保留了 `http.send`、`opa.runtime`、各类编码 / 加密 / 文件或自定义高危 builtin，策略仍可获得较强能力；需要按威胁模型逐项审。
6. **数据路径与外部源 / resolver**：自定义 resolver、external data、`inmem` 之外的存储可能引入额外能力，需结合部署确认。

---

## 7. 落地建议：让“不支持的规则”始终是错误而不是决定

1. **同一份 caps 贯穿三处**：CI（`opa check/build --capabilities caps.json`）、策略发布门禁、以及**运行期在用编译器**（自建 ast/rego 装配时 `ast.NewCompiler().WithCapabilities(caps)`；若注入 `rego.Compiler(c)`，务必在 `c` 上设置并自行 `Compile`，不要依赖 `rego.Capabilities(...)`）。
2. **从当前版本全量清单做减法**，保留 `equal/eq/assign` 等核心 builtin 与 `features: ["rego_v1"/"rego_v2", ...]`，用真实策略全集验证；把 caps 文件纳入代码评审与制品库。
3. **把编译 / 激活错误当发布阻断项**：检查 `Compiler.Failed()` / `Errors`、`bundle.Activate` 错误；坏策略不得 rollout。确认 bundle 失败时 readiness 失败或保留 last-good，而不是暴露空编译器。
4. **准入数据调用开启错误显性化**：Data API 加 `?strict-builtin-errors=true`，或 Go 侧用 `rego.StrictBuiltinErrors(true)` / `rego.BuiltinErrorList` 并在列表非空时 fail-closed，避免“运行时 builtin 出错 → deny 为空 → 被当允许”。
5. **Webhook 必须区分三类结果（§5）**：传输 / 超时 / 非 200 / OPA 错误体一律按失败处理；K8s `failurePolicy: Fail`（结合 `timeoutSeconds` 与可用性评估）；只有在“HTTP 200 且无错误且显式读到决定字段”时才按策略结果准入；空 / 缺字段按默认拒绝处理，除非组织明确选择“空 deny=允许”。
6. **审计实际 builtin 面**：盘点 `rego.Function*`、`topdown.RegisterBuiltinFunc`、全局 `ast.BuiltinMap` 扩展、自定义 resolver 与 wasm host functions；必要时叠加 `WithUnsafeBuiltins` 作为纵深防御（但不要把它当白名单替代品）。
7. **慎用求值期假设**：不要把 caps 当作针对恶意策略的运行时沙箱；它是兼容性 / 左移强制机制。若要运行不可信策略，还需配合 `AllowNet: []`、资源 / 超时 / 内存限制、隔离进程等。

---

## 附录 A：可复现实验方式

离线构建二进制（本机已用 go1.26.11 验证）：

```bash
export PATH=/srv/fb2/toolchains/go1.26.11/bin:$PATH GOTOOLCHAIN=local GOPROXY=off
go build -o /tmp/capbin/opa .
/tmp/capbin/opa version           # v1.23.0-dev, commit 6824432...
/tmp/capbin/opa run --help | grep -i capab   # 无输出：run 不支持
/tmp/capbin/opa check --help | grep -i capab # 有 --capabilities
```

最小 caps 文件与校验：

```json
{ "builtins": [], "features": ["rego_v1"] }
```

```bash
opa check --capabilities=empty-caps.json deny.rego   # 退出码 1，undefined function ...
```

库层面的关键断言（临时验证程序已在本环境跑过并删除，未留在仓库；可用下列要点重建）：

```go
caps := &ast.Capabilities{Builtins: []*ast.Builtin{}}
c := ast.NewCompiler().WithCapabilities(caps)
c.Compile(map[string]*ast.Module{"t.rego": mod})
_ = c.Failed() // true；c.Errors 含 "undefined function ..."

// 绕过编译直喂 topdown：空 caps 不阻止全局注册的 builtin
qrs, err := topdown.NewQuery(body).WithCompiler(
    ast.NewCompiler().WithCapabilities(caps),
).WithStore(store).WithTransaction(txn).Run(ctx)
```

> 实验产物 OPA 二进制位于仓库外的临时目录（`/srv/fb2/tmp/u02l-fb/capbin/opa`），策略样例与 server 日志在 `/srv/fb2/tmp/u02l-fb/captest/`，均不属于本 git 工作树。

# 模块语言版本、包替换与规则发布的边界分析

范围：同一个授权策略包（bundle）内多个 `.rego` 模块声明不同 Rego 语言版本时，
默认版本、清单覆盖（`rego_version` / `file_rego_versions`）与编译失败三者之间
各自负责什么；包替换（activation）在什么时刻把"候选规则"变成"已生效规则"；
以及无效版本更新为什么可能留下半完成的包。

本文只做分析与结论，不修改代码。文中的代码坐标基于本仓库当前分支
（`task/337`，基点 `6824432`）。

---

## 1. 结论摘要

1. **版本不是单一来源，而是四层合成的结果**：运行时默认版本 → bundle 清单全局版本
   → 清单 per-file 覆盖（glob）→ 模块自身 span（由解析基线 + `import rego.v1` /
   `import rego.v2` 抬高）。四层任何一层给错，最终"规则能不能发布"的结论都可能翻转。
2. **"已生效"的判定边界是一次存储事务的提交**。`Activate` 在事务里先擦除旧根、
   再编译"旧剩余模块 + 新包模块"、最后写入数据/策略/清单；闭包返回错误 ⇒
   `Abort` ⇒ 旧决策面保持完整。这条不变式在当前实现中**基本成立**（已用实验验证）。
3. **但"无效版本"的拦截点并不统一**：
   - reader/解析期会拒绝非法的 `rego_version`、`file_rego_versions` 与无法在声明版本下
     解析的模块 —— 整包被拒，旧包继续生效（安全）。
   - delta bundle 走完全不同的路径：只比较 roots/wasm，**不校验版本**，然后把清单
     整体写回存储（已实测：存储里的 `rego_version` 被 delta 清单覆盖）。
   - `Bundle.RegoVersion(def)` 对非法整数**静默回退到默认值**，被 merge、discovery
     等派生路径使用，可能把"非法"洗成"合法"后再落盘。
4. **已生效规则与候选规则的"账本"是两套**：存储/编译器里的是已生效规则，
   `Status.ActiveRevision` + etag + `LastSuccessfulActivation` 是它的对外摘要；
   而下载、解析、编译中的对象只是候选，不提交就不可见。当前实现里有若干路径会让
   **存储已更新、编译器未更新**（或反之），这才是"半完成"的真实来源，而不是事务回滚本身。
5. 运维可见性缺口：非 AST 类型的错误（包括 `unknown bundle rego-version`）只写入
   `Status.Message`，不进入 `Status.Errors`，按 `errors[]` 告警的监控会漏掉版本拒绝。

---

## 2. 版本决定的调用链与责任边界

### 2.1 四层来源

| 层 | 所有者 | 载体 | 作用 | 关键位置 |
|---|---|---|---|---|
| ① 运行时默认 | OPA 部署者 | `--v0-compatible` / `--v1-compatible` / `--v2-compatible`、`ast.DefaultRegoVersion` | 仅在清单未声明时生效 | `v1/runtime/runtime.go:327`、`v1/ast/rego_version.go:31`（v1 包默认 **v1**）、`ast/ast.go:1012`（deprecated shim 默认 **v0**） |
| ② bundle 全局清单 | bundle 发布者 | `.manifest` 的 `rego_version` | 覆盖运行时默认，整包所有未命中覆盖的文件 | `v1/bundle/bundle.go:157`、`:840` |
| ③ per-file 覆盖 | bundle 发布者 | 清单 `file_rego_versions`（相对 bundle 根的 glob，按键排序，首个匹配生效；重叠行为文档定义为未定义） | 单文件覆盖 ② | `v1/bundle/bundle.go:165`、`:1418` |
| ④ 模块自身 span | 模块作者（通过源码） | 解析基线 + `import rego.v1` / `import rego.v2` 抬高 `max` | 编译器按 `Min` 解析、按 `Max` 决定启用哪些 v1/v2 检查 | `v1/ast/parser_ext.go:757-800`、`v1/ast/rego_version.go:99-200`、`v1/ast/compile.go:2614` |

优先级（解析时）：**③ > ② > ①**，且 ④ 记录的是"该模块实际以什么基线被解析、
用到了多高的语言特性"，不再回头改写 ②/③。

两个容易混淆的细节：

- `RegoVersionSpan` 的 `Min` 是"按哪个版本解析"，`Max` 是"用到了哪个版本的语言特性"。
  `RegoV0CompatV1` 展开为 `[v0, v1]`，所以同一份源码可以同时满足 v0 与 v1 的检查。
- 没有 span 的模块（手工构造、未解析）才使用 `Compiler.WithDefaultRegoVersion`；
  若编译器默认也是 `RegoUndefined`，`moduleRegoVersion` 会直接报
  `cannot determine rego version for module`（`v1/ast/compile.go:2615-2623`）。
  这是显式失败，不是静默回退。

### 2.2 责任边界（谁应该为"版本错"负责）

| 组件 | 负责 | 不负责 |
|---|---|---|
| 模块作者 | 源码能在声明的基线版本下解析；`import rego.v1/v2` 与源码特性一致 | 清单里写什么版本 |
| bundle 发布者 | 清单全局/逐文件版本与包内源码一致；不同版本模块混装时正确使用 `file_rego_versions` | 运行时的 `--v*-compatible` 默认值 |
| reader（`v1/bundle`） | 用 ②③ 覆盖 ① 后解析每个模块；拒绝非法整数与解析不了的模块 | 判断两个模块版本混装是否"语义兼容" |
| 编译器 | 按每个模块的 `Min` 解析结果做版本相关检查（strict 类检查按 `Max ≥ v1` 启用） | 重新解释清单 |
| 插件/激活器 | 把"解析 + 编译 + 写入"放进一个事务；失败则中止并保留旧包 | 校验清单版本的合法性（依赖 reader） |
| 存储 | 记录每个模块实际解析版本（`/system/modules/<id>/rego_version`）供后续擦除/重编译复用 | 在 `loadCompilerFromStore` 中被读取（当前未读，见 §5.4） |

关键结论：**目前没有任何一个组件在"替换动作"这一层校验整包的有效版本集合。**
校验散落在 reader（清单层/文件层）和编译器（模块层），而 delta 路径两处都不经过。

---

## 3. 编译失败与"能否发布"

### 3.1 一次激活的确定顺序

`activateBundles`（`v1/bundle/store.go:432`）在**同一个写事务**内依次：

1. 计算要擦除的旧根与新根，检查多包 roots 重叠（`hasRootsOverlap`）；
2. 应用 delta 补丁（若有）；
3. `eraseBundles`：擦除旧数据/策略/清单/etag/wasm，并返回**剩余**（其他包或
   同名包外）的已解析模块；这里重解析策略时会参考
   `/system/modules/<id>/rego_version`（`erasePolicies` 的 `parserOptsFor`，`:789-810`）；
4. 校验懒加载数据不越界；
5. `compileModules`：把"编译器已有模块 + 剩余模块 + 外部模块 + 新包全部模块"
   放进**一个**编译器编译（`:1015`）；失败 ⇒ 返回 `compiler.Errors` ⇒ 事务中止；
6. `writeDataAndModules`：写数据、策略、`/system/modules` 版本信息；
7. `CheckPathConflicts`：数据/虚拟文档冲突检查；
8. 写清单与 etag；
9. （授权策略场景）`VerifyAuthorizationPolicySchema` 在 `compileModules` 尾部执行
   （`internal/compiler/utils.go:48`），只对授权决策引用可达的规则做 schema 校验。

因此：**编译失败、冲突失败、授权策略 schema 失败，都落在提交之前**，调用方
（`plugins.Txn`）`Abort`，旧数据与旧策略原样保留。已实测：一次 unsafe-var 编译失败后，
存储中的数据、revision、策略列表仍是旧包的内容。

### 3.2 谁"发布"了规则

提交成功后的发布动作有两处：

- 存储层面：数据与策略随事务提交可见；
- 编译器层面：`plugins.SetCompilerOnContext(txnCtx, compiler)`（`v1/plugins/bundle/plugin.go:708`）
  把编译器挂到事务上下文，`Manager.onCommit` 在提交回调里 `setCompiler`
  （`v1/plugins/plugins.go:1159`）。若上下文没有编译器（例如 HTTP `PUT /v1/policies`、
  用户自建加载器），`onCommit` 会**回退到 `loadCompilerFromStore` 重新编译**。

"已生效"的准确定义应是：**存储已提交，且管理器持有的编译器与存储内容一致**。
只满足前者就是半完成状态（见 §5.4）。

### 3.3 失败时的可见性

- `Status.SetError`：AST 错误进 `Errors[]`（`Message` 固定为 compile module error）；
  HTTP 错误单独处理；**其余错误（包括 `unknown bundle rego-version 3 for file '...'`）
  只写 `Message`**（`v1/plugins/bundle/status.go:65-97`）。
- `Status.ActiveRevision` / `LastSuccessfulActivation` 保持上一次成功值；
- 失败后 `Plugin.process` 会把 etag 回退到上一次成功值（`plugin.go:545/568/582`），
  迫使下一轮重新下载同一（坏）包，而不是跳过。

实测：reader 拒绝非法版本后，插件状态里 `Errors` 为空、`Message` 有值，
`ActiveRevision` 与 etag 仍是 `rev-1` / `etag-1`，存储 revision 仍是 `rev-1`。

---

## 4. 已生效规则 vs 候选规则

### 4.1 定义

| 概念 | 含义 | 存放/可见位置 | 何时进入 |
|---|---|---|---|
| **候选模块** | 刚下载、尚未提交的 `.rego` 及清单 | 进程内 `bundle.Bundle.Modules[*].Parsed`，不可查询 | 下载 → `Reader.Read` 解析成功 |
| **候选编译器** | 把旧剩余模块 + 新模块一起编译得到的 `*ast.Compiler` | 事务上下文（`storage.Context`），提交前外部不可见 | `compileModules` |
| **已生效规则** | 存储中的策略 + 数据，以及管理器持有的与之一致的编译器 | `/policies`、`/data`、`Manager.GetCompiler()` | 事务 `Commit` + `onCommit` |
| **已生效摘要** | 对外宣告的版本 | `Status.ActiveRevision`、`LastSuccessfulActivation`、`/system/bundles/<name>/...`、etag | 激活成功后 |

### 4.2 状态迁移

```
下载/读取 ──失败──> 旧包保持生效，status.Message/Errors 记录，etag 回退
   │
   └─成功─> [候选] 解析(按 ②③ 覆盖 ① 的版本) ──失败──> 同上（整包拒收）
                 │
                 └─> 事务内擦除+编译+写入 ──编译失败──> Abort，旧包保持生效
                         │
                         └─Commit─> [已生效] 并 setCompiler；ActiveRevision=新 revision
```

要点：

- **候选阶段的任何失败都不会产生"部分已生效规则"**，因为擦除与写入在同一事务里，
  失败即回滚（已验证）。
- 真正的风险不在事务边界，而在**提交成功但两侧不一致**的路径：存储已换新，
  编译器没跟上（或版本记录丢失导致后续重编译失败）。这类路径不会自动回滚，
  因为事务本身是成功的。
- `rego` 包（SDK 风格）的 bundle 加载同样复用一个写事务：`Rego.compileModules`
  调 `bundle.Activate`，失败则 `Eval` 中止事务（`v1/rego/rego.go:2221-2255`、`:2930-2940`），
  语义与插件一致。

---

## 5. 已验证的危险路径

以下每条都用临时测试实际跑过（测试文件未保留）。运行方式见 §7。

### 5.1 delta bundle 完全绕过版本校验，并整体覆盖清单

`activateDeltaBundles`（`v1/bundle/store.go:617`）只做两件事：
用 `equalWasmResolversAndRoots` 比较 roots/wasm（**不比较 `rego_version`**），
然后 `writeManifestToStore(opts, name, b.Manifest)` 把 delta 的清单整体写回。

实测：先激活 `rego_version: 0` 的快照包，再激活 `rego_version: 2` 的 delta 包，
存储中 `/system/bundles/b/manifest/rego_version` 从 `0` 变成 `2`，激活返回 nil。
一个非法值（如 `9`）同样会被写入。之后 `ReadBundleManifestFromStore` 的消费者
（以及把该清单当作事实依据的运维流程）会读到错误版本。

**责任边界问题**：delta 的清单语义本应"只表达 roots/wasm 约束"，却承担了
覆盖版本事实的副作用。版本合法性校验在快照路径由 reader 完成，delta 路径没有对应组件。

### 5.2 `Bundle.RegoVersion(def)` 静默回退

`v1/bundle/bundle.go:1377-1385`：清单整数非法时 `RegoVersionFromIntStrict` 出错，
函数**丢弃错误并返回 `def`**。它被：

- `Reader.Read` 用于确定解析默认版本（`:840`）；
- `MergeWithRegoVersion`（`:1617`、`:1694`）；
- discovery 评估 discovery 包（`v1/plugins/discovery/discovery.go:558`）；

使用。对 reader 来说尚可接受（随后 `validateAndInjectDefaults` 会拒绝），
但对 **merge/派生**路径意味着：非法版本被"洗"成默认值并写入新清单，之后再也看不出原始非法输入。

对照：已废弃的 `ast.RegoVersionFromInt` 把任何未知值强转成 v0
（`v1/ast/rego_version.go:61`），而 strict 版本报错（`:73`）。二者语义相反，
是给外部调用方准备的陷阱。

### 5.3 per-file 版本缓存只按 map 长度失效

`numericRegoVersionForFile`（`v1/bundle/bundle.go:1418-1443`）用
`len(FileRegoVersions) != len(compiledFileRegoVersions)` 判断是否需要重建 glob 缓存。

`MergeWithRegoVersion` 的单包分支（`:1613-1622`）会**原地替换**
`result.Manifest.FileRegoVersions`；长度相同（同一批文件、不同版本值）时缓存不失效。
实测：把一个此前解析为 v0 的文件在合并后按合并参数改为 v1，`RegoVersionForFile`
仍返回旧缓存的值（甚至在 map 已清空时仍能命中旧 pattern）。

同时 `Manifest.Copy`（`:248-267`）**不复制 `FileRegoVersions` map**，只做结构体浅拷贝：

- 实测 `Copy()` 返回的清单与原清单共享同一个 map 与同一份 glob 缓存底层数组，
  对副本的修改会泄漏到原清单；
- 版本解析结果依赖缓存指针，跨清单共享缓存意味着"改一个副本，另一个清单的解析结论也跟着变"。

`Bundle.Copy`（`:1485`）依赖 `Manifest.Copy`，因此 optimizer 等复制路径同样受影响。

### 5.4 提交后重编译丢失模块版本记录（真正的半完成状态）

`loadCompilerFromStore`（`v1/plugins/plugins.go:1210`）列出全部策略，
**全部用运行时 `ParserOptions` 重新解析**，完全不读 `/system/modules/<id>/rego_version`。

实测（运行时默认 v1，激活 `rego_version: 0` 的包，其模块在激活时正确按 v0 解析并联编成功）：
后续 `loadCompilerFromStore` 重解析同一模块时报
`rego_parse_error: 'if' keyword is required before rule body`。触发场景：

- `onCommit` 的编译器回退（HTTP 写策略、用户自建加载器）：
  `compiler, _ = loadCompilerFromStore(...)`（`:1167`）**丢弃错误**。
  实测此时管理器仍持有旧编译器（sentinel），即**存储已有新策略、生效编译器是旧的**；
- `Manager.Start` 注册外部数据源后的重编译（`:937`）：错误会被返回，导致 **OPA 启动失败**。

注意对比：`activateBundles` 内部的擦除/重编译路径（`erasePolicies`）**是**读
`/system/modules` 的（`v1/bundle/store.go:789-810`）。两条重编译路径对版本记录的
使用不一致，是当前实现里最明确的"责任边界缺口"。

相关放大因素：`writeModuleInfoToStore`（`:901-932`）**只在模块版本与运行时默认不同时
才写记录**。实测运行时 v0 消费 v0 包、运行时 v1 消费 v1 包时，`/system/modules`
根本不存在。一旦运行时默认改变（例如运维从默认 v1 切到 `--v0-compatible`，
或跨版本重启），存储中没有任何信息能还原"当初是按什么版本解析的"。

### 5.5 `/system/modules` 可被 bundle 数据覆盖，从而阻塞后续替换

模块版本记录位于 `ModulesInfoBasePath = /system/modules`（`v1/bundle/store.go:41`）。
当 bundle 的 `roots` 含 `""` 时，`writeData` 会把数据文件按路径写入存储，
包括 `data.system.modules`。

实测：一个 data 中带 `{"system":{"modules":{"x":{"rego_version":9}}}}`、
`roots: [""]` 的包激活成功，并把 `/system/modules` 覆盖为非法内容；
下一次激活时 `erasePolicies` 读模块信息失败：
`failed to read module info from store: corrupt rego version: unknown rego-version 9`，
**激活中止**。旧规则仍生效（fail-closed 方向正确），但更新通道被封死，
且这是"无效版本导致包无法发布"的一个真实入口。

### 5.6 被覆盖/未覆盖的拒绝点一览

| 输入 | 拒绝位置 | 结果 | 旧决策面 |
|---|---|---|---|
| 清单 `rego_version: 3`，无模块 | `validateAndInjectDefaults`（`bundle.go:367`） | 读包失败 | 保持 |
| 清单 `rego_version: 3`，有模块 | 解析循环 `RegoVersionForFile`（`:853`） | 读包失败（错误信息带文件名） | 保持 |
| `file_rego_versions` 非法值 | 解析循环或清单校验（`:372`） | 读包失败 | 保持 |
| 模块在声明版本下语法不合法 | `ast.ParseModuleWithOpts`（`:860`） | 读包失败 | 保持 |
| 编译错误 / unsafe var / 冲突 | `compileModules` / `CheckPathConflicts` | 事务中止 | 保持（实测） |
| 授权策略 schema 不符 | `VerifyAuthorizationPolicySchema` | 事务中止 | 保持 |
| **delta 清单 `rego_version` 非法** | **无** | 清单被写入存储（实测） | 保持，但版本事实被污染 |
| **`Bundle.RegoVersion` 遇到非法值** | **无（静默回退）** | 被当作默认版本继续 | 取决于调用方 |

由此可见：**"无效版本不能覆盖旧决定"在快照路径上成立，在 delta 与派生路径上不成立。**
成立的原因是"校验先于破坏性写"，不成立的原因是"缺少校验或校验被吞"。

---

## 6. 建议的边界收紧（按优先级）

1. **delta 清单不得携带/覆盖版本事实。** 要么拒绝 delta 中的 `rego_version`，
   要么在 `activateDeltaBundles` 内用 `RegoVersionFromIntStrict` 校验并保持存储值不变。
2. **`loadCompilerFromStore` 必须按 `/system/modules` 还原每个模块的版本**
   （复用 `erasePolicies` 的 `parserOptsFor` 逻辑），并让 `onCommit` 不再丢弃错误：
   重编译失败应保持"已生效编译器"与"存储"的一致性策略显式化，而不是静默分叉。
   同时 `Manager.Start` 的外部源重编译失败会直接阻断启动，应在文档中明确。
3. **始终记录模块版本**（或记录"运行时默认版本"本身），使重放不依赖当前的命令行旗标。
4. **保护 `/system` 不被 bundle 数据写入**（在 `writeData` 处过滤，或明确文档化
   `roots: [""]` 会覆盖 `data.system`），否则一条数据即可让后续包无法发布。
5. **修复 `Manifest.Copy` 的 map 浅拷贝与 glob 缓存共享**，并把
   `numericRegoVersionForFile` 的失效条件从"长度"改成内容比较（或显式清空缓存）。
6. **让 `Bundle.RegoVersion` 返回错误**（或至少区分"未声明"与"非法"），
   在 merge/discovery 路径上保留非法输入的事实。
7. **运维可见性**：版本类错误应进入 `Status.Errors`，否则基于 `errors[]` 的告警会漏报。

---

## 7. 验证方式与限制

- 所有结论均以临时 Go 测试在本仓库内执行验证（测试文件已删除，工作树无改动）：
  1. `Manifest.Copy` 共享 `FileRegoVersions` 与 glob 缓存；
  2. `numericRegoVersionForFile` 在 map 长度不变时返回缓存旧值；
  3. `Bundle.RegoVersion` 对 `3` 静默返回默认值；`RegoVersionFromInt(3) == v0`，
     `RegoVersionFromIntStrict(3)` 报错；
  4. delta 激活把存储清单 `rego_version` 从 0 改为 2；
  5. 运行时 v1 + `rego_version: 0` 包：激活成功时写入
     `/system/modules/b/.../rego_version: 0`，但 `loadCompilerFromStore`
     重解析失败（`if` / `contains` required）；
  6. `onCommit` 在重编译失败后保留旧编译器（存储与编译器分叉）；
  7. bundle data 写入 `/system/modules` 后，下一次激活报 `corrupt rego version`；
  8. 编译失败（unsafe var）激活：数据、revision、策略全部保持旧值；
  9. reader 拒绝非法版本：`ActiveRevision`/etag 保持 `rev-1`/`etag-1`，
     `Errors` 为空、`Message` 有值；
  10. deprecated `bundle/` shim 的 reader 默认 v0，`v1/bundle` 默认 v1：
      同一份 v0 源码前者可读、后者报错 —— 这正是"同一包在不同消费端被解释成不同版本"的最小例。
- 本机默认 `go` 会尝试下载 `go1.26.0` 工具链而离线失败，验证时改用本机
  `/srv/fb2/toolchains/go1.27.4`（`GOTOOLCHAIN=local GOPROXY=off`）。这不影响结论，
  但如需在 CI 复跑，请使用仓库声明的 Go 版本。
- 未做的验证：多实例/磁盘存储在运行期间切换默认版本的场景（§5.4 的放大因素由此推断），
  以及自定义 `bundle.RegisterDefaultBundleActivator` 的扩展实现 —— 后者可以完全绕过
  `activateBundles` 的事务语义，此时 §3 的原子性结论不再自动成立。

---

## 8. 关键代码坐标（速查）

| 主题 | 位置 |
|---|---|
| 默认版本（v1 包 / shim） | `v1/ast/rego_version.go:31`、`ast/ast.go:1012` |
| 版本 span 语义 | `v1/ast/rego_version.go:99-200` |
| 模块 span 生成 | `v1/ast/parser_ext.go:757-800` |
| 编译器按模块取版本 | `v1/ast/compile.go:1240`、`:1279`、`:2614-2627` |
| 清单字段与校验 | `v1/bundle/bundle.go:157-167`、`:347-375` |
| reader 解析顺序（先解析后校验） | `v1/bundle/bundle.go:840-874`、`:902` |
| 静默回退 | `v1/bundle/bundle.go:1377-1385` |
| per-file 解析与缓存 | `v1/bundle/bundle.go:1393-1443` |
| 合并与版本写入 | `v1/bundle/bundle.go:1605-1695` |
| 激活事务 | `v1/bundle/store.go:432-560` |
| delta 激活 | `v1/bundle/store.go:617-661` |
| 模块信息读写 | `v1/bundle/store.go:741-787`、`:901-932` |
| 重编译（忽略模块信息） | `v1/plugins/plugins.go:1210-1246` |
| onCommit 丢弃错误 | `v1/plugins/plugins.go:1159-1172` |
| 插件激活与状态 | `v1/plugins/bundle/plugin.go:531-632`、`:634-710` |
| 事务提交/中止 | `v1/storage/storage.go:95-108` |
| 授权策略 schema 校验 | `internal/compiler/utils.go:48` |
| 运行时旗标 | `v1/runtime/runtime.go:327-346` |
| HTTP 策略写入（触发回退路径） | `v1/server/server.go:2192-2296`、`:2591-2614` |

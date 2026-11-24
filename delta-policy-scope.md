# Delta 策略包补丁作用域与多补丁发布一致性分析

- 仓库：`github.com/open-policy-agent/opa`，分支 `task/331`，基线 `6824432`
- 分析对象：`v1/bundle/store.go`（激活 / 补丁应用）、`v1/bundle/bundle.go`（Reader 校验与类型判定）、`v1/storage/{inmem,storage}.go`（事务语义）、`v1/plugins/{bundle/plugin.go,plugins.go}`（插件激活与编译器发布）
- 方法：静态阅读 + 本地 `go1.26.11` 运行临时测试（测试文件仅用于取证，**已删除**，未留在工作区）。文中标注「已验证」的结论均来自实际运行输出，标注「代码推导」的来自控制流阅读。

---

## 0. 结论摘要

1. **补丁作用域只在 Reader 层校验，`Activate` 自身不校验。** 校验点是 `Manifest.validateAndInjectDefaults`（`v1/bundle/bundle.go:415-421`），比较的是 **原始字符串**；真正落盘时 `applyPatches`（`store.go:1257`）先做 URL/JSON-Pointer 反转义。两层命名空间不一致，因此「通过校验」不等于「写到声明的根下」。
2. **作用域约束的参照物是存储里可被补丁改写的 manifest 记录，而不是不可变的「既有治理根」。** `/system/bundles/<name>/manifest/roots` 本身就在补丁可写的数据命名空间内；补丁路径没有任何保留路径保护。声明根为 `"system"` 或 `""` 的 bundle 可以改写、甚至整体擦除其它 bundle 的治理根记录。
3. **多项发布时存在「补丁已应用、随后被同一次调用的 snapshot 擦除」的顺序窗口。** `activateBundles` 先应用 delta（`store.go:468-473`），再按 snapshot 的根擦除（`store.go:477`）；而 delta 的 `revision` / `etag` 在擦除之前就已写入（`store.go:650-657`）。结果是：数据丢失、状态报告成功、etag 已持久化 → 服务端下次收到 304，数据永久不回补。
4. **`patch.json` 的 `data` 为空数组时，bundle 会被重分类为 snapshot**（`bundle.go:1561-1566`：`Type()` 为 delta 当且仅当补丁列表非空）。于是一次「只想改数据」的下发会：擦除旧根下的**全部数据与策略**、允许改变 roots、并绕过所有 delta 专属检查（禁止 data/policy/wasm 文件、禁止签名豁免）。
5. **失败边界对「返回错误」是干净的：整事务回滚，查询不可见，revision/etag 不变，编译器不发布（已验证）。** 但对「panic」不是：`upsert` 到 `/` 会在 `store.go:1267` 执行 `path[:len(path)-1]` 触发 `slice bounds out of range [:-1]`；`storage.Txn`（`v1/storage/storage.go:95-108`）没有 `defer`/`recover`，inmem 写锁不会释放（已验证：后续写事务永久阻塞），且插件链路全程无 `recover`，在真实 `opa run` 中会直接终止进程。该 payload 可被 Reader 正常接受（已验证）。
6. **「无法完整落地的更新不得被解释为已生效」这句话，在错误路径成立，在成功路径不成立。** 上述第 2/3/4 条都属于「返回 nil、状态标记 activated，但补丁/策略没有按预期生效或未生效部分不可区分」。对租户授权而言，最危险的组合是：撤销类补丁丢失 + revision 已推进 → 旧授权继续有效，而运维侧看到的是新 revision。

---

## 1. 激活与事务模型

### 1.1 调用链

```
plugins/bundle/plugin.go:563  process()
  └─ plugin.go:634 activate()          开 write txn（storage.Txn → Commit/Abort）
       └─ plugin.go:702/705 bundle.Activate / ActivateLegacy
            └─ store.go:432 activateBundles
                 ├─ store.go:439-459  按 b.Type() 分类 delta / snapshot，算擦除根集合
                 ├─ store.go:463      hasRootsOverlap（对本次全部 bundle）
                 ├─ store.go:468-473  activateDeltaBundles  ← 先应用补丁
                 ├─ store.go:477      eraseBundles          ← 后擦除 snapshot 根
                 ├─ store.go:541      compileModules（仅 snapshot 模块）
                 ├─ store.go:546      writeDataAndModules（仅 snapshot 数据）
                 ├─ store.go:550      CheckPathConflicts
                 └─ store.go:554-566  写 manifest / etag / wasm
```

`plugin.go:649-651`：delta 复用 manager 上已有的编译器（不重新编译策略）；`plugin.go:708` 把该编译器挂到 txn context 上；提交后 `plugins.go:1159-1187` 的 `onCommit` 才把它发布为全局编译器。

### 1.2 事务可见性

- 激活全程在同一写事务内（`plugin.go:640`）。错误返回 → `storage.Txn` 调 `Abort`（`v1/storage/storage.go:102-105`），提交触发器不运行，新编译器不发布。
- inmem 的读事务只看已提交的 `db.data`，事务内的 `updates` 列表只在 `txn.Read` 里按「新更新覆盖旧更新」合并（`v1/storage/inmem/txn.go:258-298`）。因此**激活中间态对并发查询完全不可见**。
- 因此：只要 `Activate` 返回错误，查询侧看到的仍是激活前的数据与策略——这一点已验证（部分补丁失败后 `root`、`revision` 均为旧值）。

### 1.3 顺序（关键）

`store.go:468` 与 `store.go:477` 的先后顺序，是第 3 条结论的根因：**本次调用内 delta 的写入发生在 snapshot 擦除之前**。擦除集合来自两处：

- 该 bundle 在存储中的旧根（`store.go:446-452`）
- 新 manifest 声明的根（`store.go:455-457`）

只要同一次调用里另有一个 snapshot（不同 name）覆盖了 delta 写入的路径，补丁就会被静默抹掉。

---

## 2. 作用域约束的现状

### 2.1 Reader 层（唯一的补丁作用域校验）

`bundle.go:415-421`：

```go
for _, patch := range b.Patch.Data {
    path := strings.Trim(patch.Path, "/")
    if !RootPathsContain(roots, path) {
        return fmt.Errorf("manifest roots %v do not permit data patch at path '%s'", roots, path)
    }
}
```

- 校验发生在 `bundle.go:423-425` 的 lazy 提前返回**之前**，所以插件默认的 lazy 模式也会执行（已验证）。
- 比较用的是未解码的字面量分段（`rootContains`，`bundle.go:1789-1806`）。
- 无 `.manifest` 时根默认是 `[""]`（`bundle.go:189-194`），它对任何路径都「包含」，因此**无 manifest 的单 bundle 部署等于不做任何作用域约束**。

### 2.2 Activate 层（不存在校验）

`activateDeltaBundles`（`store.go:617-661`）只做一件事与作用域有关：把 delta 的 manifest 与**存储中该 name 的 manifest** 比较（`store.go:620-637`）。不做补丁路径与根的比对。已验证：直接构造 `Bundle{Roots: ["a"], Patch: "/b/x"}` 调用 `Activate` 会被接受并写入 `/b/x`。

真实路径上这两层的差别在于：走 `NewReader` 的入口（`opa run --bundle`、bundle 插件、`opa eval -b`）有校验；`bundle.Activate` 作为公开 API 的编程式调用（含 `v1/rego` 的 `ParsedBundle`、`initload.InsertAndCompile`）没有。

### 2.3 根集合比较

`equalWasmResolversAndRoots`（`bundle.go:288-300`）用 `rootSet()` 做**原始字符串集合**相等比较，不做 trim、不做反转义。可靠性依赖两侧都已被 `validateAndInjectDefaults` 归一化（`bundle.go:353-356` 只去首尾 `/`）。已验证：`"/a"` 校验后变 `"a"`，与存储侧相等；但若编程式构造 `"/a"` 会误报「roots 与存储不一致」。

### 2.4 保留路径

全仓库没有对 `/system`、`/system/bundles`、`/system/modules` 的写保护。`hasRootsOverlap`（`store.go:1138-1251`）只比较 bundle 之间的根，不排除系统命名空间。因此：

- 声明根 `"system"` 的 bundle 与任何普通根都不重叠 → 允许激活；
- 激活时 `eraseData`（`store.go:725-739`）会把该根整个删掉，包括**所有 bundle 的 manifest / etag / module info**。

---

## 3. 缺口清单

严重度标注：**高** = 可导致错误授权/不可用/进程崩溃；**中** = 状态与实际不一致、运维误判；**低** = 边角一致性。

### E1（高）补丁 `upsert "/"` 触发 panic：崩溃或写锁泄漏

- 位置：`store.go:1257`（`ParsePatchPathEscaped("/" + "")` → 空 `Path`），`store.go:1267`（`path[:len(path)-1]`）。
- 触发条件：bundle 的根包含 `""`（无 `.manifest`，或显式 `roots: [""]`），`patch.json` 含 `{"op":"upsert","path":"/",...}`。Reader 校验对 `""` 放行（已验证）。
- 后果（已验证）：panic `slice bounds out of range [:-1]`。`v1/storage/storage.go:95-108` 无 `defer`，inmem 的 `wmu` 不释放 → 之后所有写事务阻塞；读事务仍可用。在不 recover 的进程里（bundle 插件、downloader goroutine，全程未找到 `recover`）则直接终止进程。
- 对比：`replace "/"` 正常（走 `txn.updateRoot`，`inmem/txn.go:153-189`），`remove "/"` 返回 `root cannot be removed`（已验证）。只有 `upsert` 会崩。

### E2（高）多项发布时的「先写后擦」：补丁丢失但记为成功

- 位置：`store.go:468-473` 早于 `store.go:477`；etag/manifest 写入在 `store.go:650-657`。
- 场景（已验证）：同一次 `Activate` 里，`snap` 由根 `a` 改为根 `b`，`tenant` 的 delta 向 `/a/grant` 写入。结果：`/a/grant` 不存在，但 `tenant` 的 `revision=d1` 已写入 `system.bundles.tenant.manifest`，且没有错误返回。
- 放大效应（代码推导）：`plugin.go:383` 在启动时从存储读 etag 作为 `If-None-Match`。delta 的 etag 已在擦除前落库，服务端对同一 revision 回 304（`plugin.go:605-612`），**丢失的写入不会被重发**，直到下一次 revision 变化。
- 说明：插件按单 bundle 调用（`plugin.go:683`），混装来自 `bundle.Activate` 的多 bundle API、`initload.InsertAndCompile` 或自研 activator；`hasRootsOverlap` 允许 `snap` 新根 `b` 与 `tenant` 的 `a` 并存，因此这个组合能通过全部检查。

### E3（高）空补丁列表被重分类为 snapshot

- 位置：`bundle.go:1561-1566`，`Type()` 由 `len(b.Patch.Data) != 0` 决定。
- 连带失效的检查全部以 `Type() == DeltaBundleType` 为条件：
  - `bundle.go:877-894`：delta 不得包含 data/policy/wasm 文件；
  - `bundle.go:695-697`：要求签名的配置必须拒绝 delta。
- 已验证的四个后果：
  1. 无 manifest 的 `patch.json` + `{"data":[]}` 视为 **root `""` 的 snapshot**：作为唯一 bundle 时成功激活并**清空整个存储**（含注册表），返回 nil（与文档「清空全部数据」一致，但与「delta 只做增量」的运维预期不一致）。
  2. 同名已有 bundle 时，`{"data":[]}` + `.manifest roots:[a]` 会擦除根 `a` 下的**所有策略**并推进 `revision`，返回 nil（已验证：`policies=[]`，`revision=s2`）。
  3. 空补丁 + `.rego` / `data.json` 的归档会被当作 snapshot 正常安装策略（已验证：`policies=[d/a/policy.rego]`），即「delta 通道」可承载策略。
  4. 空补丁 + 不同 `.manifest roots` 可改变作用域：根由 `a` 变为 `z`，无报错（已验证）。
- 结论：**服务端不能把「本次无变更」实现为空补丁的 delta**；这也解释了文档要求「无操作时返回相同 Etag」。

### E4（高）根 `"system"` / `""` 可改写、擦除其它 bundle 的治理根

- 位置：`hasRootsOverlap`（`store.go:1138-1251`）无保留路径排除；`eraseData`（`store.go:725-739`）直接按根擦除。
- 已验证的两种形态：
  - **改写**：bundle `sys` 声明根 `["system"]`，delta 补丁 `upsert /system/bundles/tenant-a/manifest/roots = ["a","secret"]`。随后 `tenant-a` 发一个声明 `["a","secret"]` 的 delta，manifest 相等性检查（`store.go:634`）通过，补丁写入 `/secret/...` 成功。**即：补丁作用域没有受「既有治理根」约束，而是把治理根本身当成了可写数据。**
  - **擦除**：bundle `S` 声明根 `["system"]` 且不带任何 system 数据 → 激活后 `/system` 下所有其它 bundle 的 manifest/etag/module info 消失；此后 `C` 声明根 `["a"]` 可成功激活（擦除 `A` 的 `/a`、删除 `A` 的策略包 `a`），`A` 的痕迹不可查。
- 该场景不需要签名：delta 若配置允许无签名，或这些 bundle 走不同签名配置时都成立。

### E5（中）manifest 记录缺失时，delta 跳过一致性检查

- 位置：`store.go:622-625`，`storage.IsNotFound` → `continue`。
- 已验证：删除某 bundle 的 manifest 记录后，其 delta 可声明 `["a","elsewhere"]` 并写入 `/elsewhere`，成功。结合 E4，这是「擦除注册表 → 扩张根」的可组合链路。
- 注意：这是「delta 不需要前序 snapshot」的正常设计（文档明确允许），但代价是**任何能清掉 manifest 记录的操作都会解除该 bundle 的作用域约束**。

### E6（中）根/补丁路径的编码命名空间不一致 → 静默丢数据

- 位置：Reader 校验用字面量（`bundle.go:415-421`）；`applyPatches` 用 `ParsePatchPathEscaped` 做 `%XX` + `~0/~1` 解码（`store.go:1257`）；`writeData`/`eraseData` 用 `ParsePathEscaped("/"+root)`（`store.go:997, 727`）。
- 已验证：
  - 根 `["a%2Fb"]` + 数据放在 `a%2Fb/data.json`：`lookup` 用反转义后的单段 `"a/b"` 去查 `"a%2Fb"` → 查不到 → **什么都不写，激活返回成功**（静默丢数据）。
  - 根 `["a%2Fb"]` 与根 `["a/b"]` 可同时激活（overlap 按原串比较），但两者实际落在不同的字面键上（`"a/b"` 单段 vs `a` → `b`），既没有真正隔离也没有真正冲突。
  - `~1`/`~0` 只在补丁路径解码，Reader 校验不解码，因此带这两种转义的作用域检查是「偏严拒绝」或「偏松放行」取决于写法，不是一致的约束。
  - 反向的「越根」没有成功：`%2F` 解码出的 `/` 仍作为**单段**键存储，`..` 也只是字面量键（已验证 `a: {"..": {...}}`），所以没有目录穿越，但会产生查询不可达的脏键。

### E7（中）`Activate` 不校验补丁作用域

- 见 2.2。影响所有编程式调用方：嵌入 OPA 的 `v1/rego`（`ParsedBundle`）、自定义 activator、`initload.InsertAndCompile` 的多 bundle 初始化。这类调用方需要自己保证补丁路径落在根内，否则 Reader 的全部作用域保证都不适用。

### E8（低）多 delta 的应用顺序不确定

- `store.go:639` 对 `map[string]*Bundle` 直接 `range`，多个 delta 之间无序。若它们触及同一路径（例如通过 E4/E6 造成的根重叠），最终值不确定且不可复现。单个 bundle 内的补丁顺序是有序的（slice 遍历）。

### E9（低）补丁序列的隐式副作用

- `upsert` 在父路径缺失时会 `MakeDir`（`store.go:1273`），因此「先 upsert 父路径、再 remove 父路径」会留下空对象；「先 remove 不存在的路径、再 upsert」会让整个 bundle 激活失败（已验证）。补丁序列必须按「已提交状态 + 本序列已产生的状态」推演，文档只描述了单条操作的语义。

---

## 4. 可见数据、失败边界与后续策略决定

### 4.1 错误路径（已验证为干净）

| 失败点 | 事务 | 数据 | manifest/revision/etag | 编译器 | 查询侧可见 |
|---|---|---|---|---|---|
| 补丁 `remove`/`replace` 目标不存在 | Abort | 不变 | 不变 | 不发布 | 旧状态 |
| 补丁非法 op / 路径解析失败 | Abort | 不变 | 不变 | 不发布 | 旧状态 |
| `CheckPathConflicts` 失败（补丁与规则虚拟文档冲突） | Abort | 不变 | 不变 | 不发布 | 旧状态 |
| 同一调用第二个 delta 失败 | Abort | 第一个 delta 也不可见 | 不变 | 不发布 | 旧状态 |
| panic（E1） | **未 Abort** | 内存中不可见 | 不变 | 不发布 | 旧状态，但**写能力被锁死/进程崩溃** |

这与「无法完整落地的更新不得被解释为已生效」是一致的：`plugin.go:563-571` 把错误写入 status（`SetError`），`LastSuccessfulActivation` 不前移，etag 回退为上次成功值（`plugin.go:544-547`），status 的 `active_revision` 仍指向旧 revision。

### 4.2 成功但不完整（本报告的核心问题）

以下情形**返回 nil 且 status 标记 activated**：

1. E2：delta 数据被同批 snapshot 擦除，`revision`/`etag` 已推进 → 查询看到旧数据（或缺失），但状态与 etag 表明更新已生效；
2. E3.2：空补丁导致策略被删除、`revision` 推进 → 查询侧授权策略变成 undefined；
3. E4：治理根被改写/擦除 → 其它 bundle 的后续 delta 以被篡改的根为准，「既有治理根」约束实际失效；
4. E6：编码不一致导致数据未写入。

对租户授权决定的直接含义：

- **撤销（remove / 覆盖）类补丁丢失**：被撤销的授权继续有效。这是唯一「安全上有害」的方向；E2 是最现实的路径（多 bundle 协同发布、rollout 顺序不当）。
- **策略模块被 E3 删除**：对 `data.<tenant>.allow` 的查询变为 undefined，最终放行还是拒绝取决于前端的授权集成（`default allow := false` 时拒绝；若集成把 undefined 视为放行，则失效开放）。
- **数据缺失**：`deny if not data.x.blocked` 这类「否定式」规则会把缺失解释为「未阻断」或按默认值处理，效果依策略写法而定，不能假设一定是 fail-closed。
- **stale compiler 风险低**：delta 不重编译，`CheckPathConflicts` 仍会在事务内对**新数据 + 现有规则**做冲突检查（`store.go:646`），所以「补丁制造与规则冲突的基础文档」会整体失败而不是半应用。

### 4.3 状态与观测

- `plugin.go:553` 的 `p.status[name].Type = u.Bundle.Type()`：由于 E3，一个「delta 通道」下发、内容为空补丁的更新会在状态里显示为 `type: "snapshot"`，与运维配置形成误导；
- E2/E4/E6 没有专门的诊断信号：日志是 `Bundle loaded and activated successfully`（`plugin.go:594-597`），只有 `revision` 变化可作事后比对，且 E4 可以连 revision 一起改写。

---

## 5. 建议

按「先堵住不可逆损失，再收敛语义」排序。以下只是方向，按 AGENTS.md 需先与维护者就改动意图达成一致，再由人类作者提交。

1. **补丁路径的纵深防御放在 `applyPatches` 内部**：解析后、写之前，用与 `eraseData`/`writeData` 相同的反转义结果，对 `b.Manifest.Roots` 做一次包含性断言；`len(path)==0` 的 `upsert` 明确报错而不是 `path[:len(path)-1]`。这同时修掉 E1、E6、E7（Reader 校验保留作为早期报错）。
2. **`/system`（含 `/system/bundles`、`/system/modules`）与空根设为保留路径**：manifest 校验阶段拒绝；`hasRootsOverlap` 中排除。修掉 E4/E5 的入口。
3. **`Type()` 改为由归档内容而非补丁数量决定**（例如记录是否读到 `patch.json`），使空补丁的 delta 仍走 delta 路径并按文档语义处理（或显式报错）。修掉 E3。
4. **把 delta 的应用顺序放到 snapshot 擦除/写入之后**，或在同一调用内检测「delta 写入路径 ∩ snapshot 擦除集合 ≠ ∅」并报错。修掉 E2。
5. **manifest 记录缺失时，对已有 bundle 的 delta 采用「不能验证即拒绝」**（可配置），而不是静默 `continue`。收紧 E5。
6. **状态/可观测性**：激活成功后校验「补丁目标路径在事务内最终可读」，失败则整体失败；至少把 delta 的 `applied_ops` 数和根写进 status。
7. 文档补充：空补丁的兼容行为（`docs/docs/management-bundles/index.md` 的 danger 段落）需要说明「它等价于 snapshot 重激活」，以及多 bundle 协同发布时的顺序语义。

---

## 6. 复现材料（供维护者评估，非对外披露）

以下 payload 均经 `NewReader`（lazy 与非 lazy 各验证一次）读取后激活。临时测试已删除，保留最小输入以便重新构造。

```
# E1：进程崩溃 / inmem 写锁泄漏
patch.json: {"data":[{"op":"upsert","path":"/","value":{}}]}
（无 .manifest，或 .manifest 声明 roots:[""]）
期望：报错；实际：panic slice bounds out of range [:-1]（store.go:1267）

# E2：补丁被同批 snapshot 擦除
1) snap  .manifest {"revision":"s1","roots":["a"]} + a/data.json
2) 一次 Activate 同时提交：
   snap  .manifest {"revision":"s2","roots":["b"]} + b/data.json
   tenant .manifest {"revision":"d1","roots":["a"]}
          patch.json {"data":[{"op":"upsert","path":"/a/grant","value":"tenant"}]}
期望：报错或保留 /a/grant；实际：返回 nil，/a/grant 不存在，
     system.bundles.tenant.manifest.revision == "d1"

# E3：空补丁重分类
.manifest {"revision":"s2","roots":["a"]} + patch.json {"data":[]}
（同名已有 roots:["a"] 的 bundle，含 a/p.rego）
实际：返回 nil，revision 变 s2，policies 为空

# E4：治理根改写 / 擦除
sys    .manifest {"revision":"s-sys","roots":["system"]}
       patch.json {"data":[{"op":"upsert",
         "path":"/system/bundles/tenant-a/manifest/roots",
         "value":["a","secret"]}]}
后续 tenant-a 发 roots:["a","secret"] 的 delta → 通过 roots 相等性检查并写入 /secret
另：S .manifest {"revision":"s1","roots":["system"]}（无数据）→ /system 下全部 bundle 记录消失

# E6：编码不一致（静默不写）
.manifest {"revision":"e1","roots":["a%2Fb"]} + a%2Fb/data.json {"grant":"tenant"}
实际：返回 nil，存储中无任何数据
```

---

## 7. 合规与后续处置

- 本报告是内部技术分析。按仓库 `AGENTS.md`，**不得**由 AI 在 issue/PR 上以用户名义发表评论或提交 PR；如要推进修复，需要人类作者先在 issue 中与维护者确认方向，并由人类撰写 PR 描述、`git commit -s` 签署。
- E1（远端内容导致进程崩溃/写锁泄漏）与 E4（作用域约束可被补丁本身改写）具备安全性质。若认定为新的安全漏洞，请先按 `https://www.openpolicyagent.org/security` 的流程处理，再考虑公开讨论与修复补丁。
- 若后续要对以上缺口做代码修改：需要同时补测试（`v1/bundle/store_test.go` 的 delta 生命周期用例是合适落点）与文档（`docs/docs/management-bundles/index.md` 的 Delta Bundles 段落），并通过 `golangci-lint run ./...`。

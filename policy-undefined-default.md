# policy-undefined-default：未定义、显式否决与默认回退的准入判定

验证基线：本仓库提交 `68244323f5a489371decebc4a7c16400dfd2df22`；使用仓库源码构建的 OPA `1.23.0-dev` 与 Go `go1.26.11` 实际执行策略和 HTTP Data API。

## 1. 最终判断

1. **“没有结果”不是 `false`，更不是 `true`，而是该查询没有解（undefined）。**
   - Go API：`Eval` 返回 `ResultSet(nil), nil`；`v1/rego/resultset.go:9-11` 明确写明空 `ResultSet` 表示 undefined query。
   - CLI JSON：`opa eval --format json data.raw.allow` 对未定义查询输出 `{}`；pretty 格式输出 `undefined`；退出码为 `0`，不是执行错误。
   - HTTP Data API：`POST /v1/data/raw/allow` 返回 `200` 和响应体 `{}`，其中没有 `result` 字段。
2. **缺失身份属性时，裸引用和局部赋值不会得到零值。** `input.identity.id` 缺失时本身无值；`id := input.identity.id` 会在该表达式处失败，当前规则不产生结果。OPA 不会把它自动赋值为 `""`、`null` 或 `false`。
3. **`default allow := false` 会把“所有同名常规规则均无果”转换成一个真实存在的 `false` 结果。** 因此准入侧看到的是显式的布尔拒绝值，而不是 undefined。
4. **显式否决是一个已经存在的决策结果**，例如 `allow := false if { not input.identity.id }`，或 `deny contains "..."` 生成非空拒绝集合。它与“没有查询结果”是两种状态。
5. **`default allow := true` 也会产生真实结果 `true`，但这是策略作者明确选择的失败开放回退**；它不同于执行层把空 `ResultSet` 私自改写成允许。
6. **OPA 没有自动的“deny 覆盖 allow”魔法。** 如果 `allow` 子规则不引用 `deny`，即使 `deny` 集合有消息，`allow` 仍可为 `true`。组合多个子规则时，必须在最终决策中显式写出 deny-overrides 逻辑。
7. 对准入执行点（PEP/Webhook），安全的契约是：**策略错误或传输错误按部署选定的 failure mode 处理；HTTP 200 但缺少 `result` / Go `ResultSet` 为空时，不得解释为允许，未显式选择 fail-open 时应拒绝。**

## 2. 仓库中的真实求值路径

CLI `opa eval` 使用 `v1/rego` API：

- `cmd/eval.go:527` 调用 `PreparedEvalQuery.Eval`。
- `v1/rego/rego.go:608-618` 进入 `Rego.eval`。
- `v1/rego/rego.go:2362-2434` 创建 `topdown.Query` 并通过 `q.Iter` 收集 `ResultSet`。
- `v1/rego/rego.go:2439-2440`：

```go
if len(rs) == 0 {
    return nil, nil
}
```

因此 undefined 是“无错误、无结果集”，调用方必须检查结果数量，不能直接读取第一个值后把零值当成策略结论。

Topdown 路径：

- `v1/topdown/query.go:558` 的 `Query.Iter` 构造 `eval` 并执行 `e.Run`。
- body 表达式从 `evalExpr`（`v1/topdown/eval.go:418`）进入 `evalStep`（`v1/topdown/eval.go:512`）。
- 赋值在编译后按局部变量统一/赋值路径执行；trace 中可直接看到 `principal = input.identity`。右侧引用 undefined 时，该表达式 `Fail`，当前 body 不再继续。
- 完整规则文档由 `evalVirtualComplete.evalValue` 处理（`v1/topdown/eval.go:4166`）。规则索引结果把三类结构分开保存（`v1/ast/index.go:44-51`）：

```go
IndexResult struct {
    Rules   []*Rule
    Else    map[*Rule][]*Rule
    Default *Rule
    ...
}
```

`v1/topdown/eval.go:4186-4225` 的实际顺序可压缩为：

```text
prev = nil

for rule in ir.Rules:              # 同名常规规则/子规则
    next = eval(rule)
    if next == nil:
        for elseRule in ir.Else[rule]:
            next = eval(elseRule)  # else 链按源码顺序回退
            if next != nil: break
    if next != nil:
        prev = next

if ir.Default != nil && prev == nil:
    eval(default)                  # 只有常规规则和 else 均无值时才走 default
else if prev == nil:
    virtualCache.Put(ref, nil)     # 仍无值：undefined，不产生查询结果
```

函数规则的对应顺序相同：先遍历 `ir.Rules`，再处理每个规则的 `Else`，最后仅在 `e.ir.Default != nil && prev == nil` 时执行默认函数（`v1/topdown/eval.go:2624-2677`）。

HTTP 路径同样保留“空结果”状态：

- `v1/server/server.go:1846` 调用 `preparedQuery.Eval`。
- `v1/server/server.go:1878-1890` 发现 `len(rs) == 0` 时直接 `writer.JSONOK(w, result, ...)`，没有设置 `result.Result`。
- `v1/server/types/types.go:324-330` 中 `Result` 字段带 `json:"result,omitempty"`，所以响应是 `{}`。

实测：

```text
POST http://127.0.0.1:18181/v1/data/raw/allow
{"input":{}}

HTTP/1.1 200 OK
{}
```

## 3. 赋值、`else` 与 `default` 的顺序

### 3.1 多个同名 `allow` 子规则是 OR 组合，不是文本顺序的首条命中

下面两条 `allow` 中任意一条成功，`data.raw.allow` 就为 `true`：

```rego
package raw

import rego.v1

allow if {
    principal := input.identity
    "admin" in principal.roles
}

allow if {
    principal := input.identity
    principal.id == input.resource.owner
}
```

对输入 `{}` 关闭索引优化后跟踪：

```text
Index data.raw.allow (matched 2 rules, early exit)
Enter data.raw.allow
Eval principal = input.identity
Fail principal = input.identity
Enter data.raw.allow
Eval principal = input.identity
Fail principal = input.identity
Fail data.raw.allow = _
undefined
```

这说明：

- `:=` 不会在属性缺失时制造默认值；
- 一条子规则失败后，OPA 会继续尝试其他同名子规则；
- 所有子规则均失败后，没有 `default` 的完整规则 `allow` 本身 undefined。

独立的 `deny contains msg if ...` 规则则是向同一个集合追加消息；OPA 官方 Kubernetes admission 指南也说明这些 deny 规则的顺序不改变结果（`docs/docs/kubernetes/primer.md:32-36`）。

### 3.2 `default` 在所有常规规则之后兜底，与其源码位置无关

```rego
package default_false

import rego.v1

default allow := false

allow if {
    principal := input.identity
    "admin" in principal.roles
}

allow if {
    principal := input.identity
    principal.id == input.resource.owner
}
```

对 `{}` 的真实 trace 顺序是两条常规规则先失败，然后才执行源码中位于前面的 default：

```text
Enter data.default_false.allow        # 第 7 行常规规则
Eval principal = input.identity
Fail principal = input.identity
Enter data.default_false.allow        # 第 12 行常规规则
Eval principal = input.identity
Fail principal = input.identity
Enter data.default_false.allow        # 第 5 行 default
Eval true
Exit data.default_false.allow early
false
```

官方文档对该语义的描述是：default value 在所有同名规则 undefined 时使用；没有 default 时，同一输入下文档仍 undefined（`docs/docs/policy-language.md:2068-2113`）。

### 3.3 顶层赋值规则也遵循“常规规则失败后才用 default”

```rego
package identity_default

import rego.v1

default role := "anonymous"

role := input.identity.role

has_id if {
    id := input.identity.id
    id != ""
}
```

输入 `{}` 时：

- `data.identity_default.role` 的 trace 先在 `__local1__ = input.identity.role` 处失败，随后执行 default，结果为 `"anonymous"`；
- `data.identity_default.has_id` 没有同名字典规则或 default，因此查询结果不存在，CLI JSON 为 `{}`；
- 查询整个 `data.identity_default` 时只能看到 `role`，看不到 `has_id`。

注意两个边界：

- 如果只是规则 body 内的局部赋值失败，失败的是**外层整条规则**；只有存在同名 `default` 时，查询该规则名才会得到回退值。
- default 函数不能救援“调用参数本身 undefined”的情况。`default role(_) := "anonymous"` 配合 `role(u) := u.role`，查询 `data.func_default.role(input.user)` 且 `input.user` 缺失时仍无结果，因为未定义参数在函数调用前就终止求值。官方文档在 `docs/docs/policy-language.md:2146-2150` 明确说明了这一点。

### 3.4 `else` 是显式的有序回退链

```rego
package fallback

import rego.v1

resolution := "admin-allow" if {
    principal := input.identity
    "admin" in principal.roles
} else := "owner-allow" if {
    principal := input.identity
    principal.id == input.resource.owner
} else := "explicit-deny-missing-identity" if {
    not input.identity.id
} else := "explicit-deny-no-match"
```

输入 `{}` 时，前两个分支的赋值失败，第三个分支中的 `input.identity.id` 先失败；由于表达式被 `not` 包裹，“子目标未定义”使 `not input.identity.id` 成功，最终得到：

```text
"explicit-deny-missing-identity"
```

`not` 的实现见 `v1/topdown/eval.go:4947-4972`：子求值没有 `defined` 时，外层取反表达式继续执行。因而：

- `input.identity.id` 缺失：该引用本身无结果；
- `not input.identity.id`：是一个成功的布尔条件；
- `missing_identity if { not input.identity.id }`：产生真实的 `true` 规则结果。

`else` 链内一旦某个分支成功，就不会继续该链后面的分支（`docs/docs/policy-language.md:2157-2164`，实现见 `v1/topdown/eval.go:4197-4213`）。这与多个独立同名 `allow if` 规则的 OR 组合不同。

### 3.5 undefined 会通过赋值和对象构造向上传播

```rego
package wrap

import rego.v1

# data.raw.allow undefined 时，整个对象值也 undefined。
decision_strict := {
    "allowed": data.raw.allow,
}

# 只有显式使用 object.get 等回退，才会把缺失路径替换成 false。
decision_object_get := {
    "allowed": object.get(data.raw, "allow", false),
}

# wrapper 自己的 default 仍按“常规规则无果后兜底”的顺序生效。
default decision_default := {"allowed": false, "source": "wrapper-default"}

decision_default := {"allowed": true, "source": "rule"} if {
    data.raw.allow
}
```

在 `{}` 上实测：

- `data.wrap.decision_strict`：无结果（CLI JSON 为 `{}`）。对象中的 `data.raw.allow` 无值，不会被补成 `false` 或 `null`。
- `data.wrap.decision_object_get`：存在，值为 `{"allowed": false}`；这是 `object.get` 显式提供的回退值，不是 OPA 对 undefined 的自动改写。
- `data.wrap.decision_default`：存在，值为 `{"allowed": false, "source": "wrapper-default"}`；因为引用 `data.raw.allow` 的常规 wrapper 规则无果，随后才使用 wrapper 的 default。

因此，“赋值”本身不是 fallback；`default`、`else`、`object.get` 或 PEP 分支才是显式 fallback，且各自的生效层级不同。

## 4. 缺失身份属性的实测矩阵

使用输入 `{}`（同时覆盖 `input.identity` 和 `input.identity.id` 缺失）：

| 策略形态 | 查询 | 结果是否存在 | 实际值 / 响应 | 准入含义 |
|---|---|---:|---|---|
| 无 default 的 `allow` 子规则 | `data.raw.allow` | 否 | CLI JSON `{}`；Go `rs == nil, err == nil`；HTTP `200 {}` | 没有 permit 结论；PEP 应 fail-closed |
| `default allow := false` | `data.default_false.allow` | 是 | `false` | 默认拒绝 |
| 显式 `allow := false if { not input.identity.id }` | `data.explicit.allow` | 是 | `false` | 显式拒绝 |
| `deny contains "missing identity.id"` | `data.explicit.deny` | 是，集合非空 | `["missing identity.id"]` | 显式否决并带原因 |
| `default allow := true` | `data.default_true.allow` | 是 | `true` | 策略选择的 fail-open |
| 结构化最终决策 | `data.combined.admission` | 是 | `{"allowed":false,"disposition":"explicit-deny",...}` | 显式拒绝 |

补充：

- `deny contains ...` 在没有任何拒绝规则命中时是**存在的空集合 `[]`**，不是 undefined。空集合表示“当前没有否决消息”；缺失身份是否属于否决条件，取决于有没有专门规则把它加入 `deny`。
- 查询整个包 `data.raw` 会得到存在的 `{}`，但其中没有 `allow` 键。准入查询应直接查询精确决策路径（如 `data.authz.admission` 或 `data.authz.allow`），并检查结果是否存在；不能因为整个包响应是一个对象就假定 `allow: false` 或 `allow: true`。

更完整的输入矩阵：

| 输入 | `data.raw.allow` | `default_false.allow` | `combined.admission` |
|---|---|---|---|
| `{}`：身份完全缺失 | undefined | `false` | `allowed=false`, `explicit-deny` |
| `{"identity":{"id":"u9","roles":["viewer"]},...}`：身份存在但无匹配子规则 | undefined | `false` | `allowed=false`, `default-deny` |
| admin，内网 | `true` | `true` | `allowed=true` |
| owner | `true` | `true` | `allowed=true` |
| admin，外网 | `true` | `true` | `allowed=false`, `explicit-deny` |

最后一行说明：如果最终决策没有引用 deny，admin 子规则仍会给出 allow。

## 5. 显式否决必须接入最终组合

下面是一个危险但常见的“断开的 deny”写法：

```rego
package antipattern

import rego.v1

default allow := false

allow if {
    "admin" in input.identity.roles
}

deny contains "external admin" if {
    "admin" in input.identity.roles
    input.network == "external"
}
```

对 admin-external 输入实测：

```text
data.antipattern.allow => true
data.antipattern.deny  => ["external admin"]
```

如果 PEP 只读取 `allow`，显式否决就被绕过。deny-overrides 必须写进最终决策，例如：

```rego
package combined

import rego.v1

# 1) 最终兜底：没有任何 admission 规则成功时，给出存在的 false 决策。
default admission := {
    "allowed": false,
    "disposition": "default-deny",
}

# 2) 显式否决优先：只要 deny 集合非空，就返回 false 和原因。
admission := {
    "allowed": false,
    "disposition": "explicit-deny",
    "reasons": deny,
} if {
    count(deny) > 0
}

# 3) 只有没有否决理由且至少一个 allow 子规则成功时，才允许。
admission := {
    "allowed": true,
    "disposition": "allow",
} if {
    count(deny) == 0
    allow
}

# OR 组合：任意一条成功即可。
allow if {
    "admin" in input.identity.roles
}

allow if {
    input.identity.id == input.resource.owner
}

# 缺失身份是显式拒绝理由，而不是依赖属性赋值得到零值。
deny contains "missing identity.id" if {
    not input.identity.id
}

deny contains "admin from external network" if {
    "admin" in input.identity.roles
    input.network == "external"
}
```

该策略在 `{}` 上的实测结果：

```json
{
  "allowed": false,
  "disposition": "explicit-deny",
  "reasons": ["missing identity.id"]
}
```

在“身份存在但所有 allow 子规则均不匹配、deny 为空”的输入上，`allow` 仍为 undefined，但 default admission 产生：

```json
{
  "allowed": false,
  "disposition": "default-deny"
}
```

## 6. 准入执行点应如何处理

### Go 集成

不要直接假设 `rs[0]` 存在：

```go
rs, err := rego.New(
    rego.Query("data.authz.admission"),
    rego.Module("authz.rego", policy),
    rego.Input(input),
).Eval(ctx)

switch {
case err != nil:
    // 策略编译/求值错误：按 PEP 配置 fail-open 或 fail-closed；安全默认建议 fail-closed。
case len(rs) == 0:
    // Undefined：没有策略结果。不得当成 allow；未明确要求 fail-open 时应拒绝。
    deny()
default:
    decision := rs[0].Expressions[0].Value
    handleStructuredDecision(decision)
}
```

如果查询的是裸布尔 `data.authz.allow`，同样必须先判断 `len(rs)`，再做布尔类型断言。`false` 是一个长度为 1、值为 `false` 的结果集；undefined 是长度为 0。

### HTTP 集成

对 `POST /v1/data/authz/admission`：

- 响应含 `result.allowed == true`：允许；
- 响应含 `result.allowed == false`：拒绝；
- HTTP 错误、超时、连接失败：属于 OPA 不可用，按部署的 failure policy 处理；
- HTTP `200` 但响应对象没有 `result`：决策 undefined。它不是传输失败，但也绝不是允许；安全默认应拒绝或转换为明确的默认决策。

OPA 文档把“OPA/决策不可用时 fail-open 还是 fail-closed”明确留给询问 OPA 的软件和部署环境决定（`docs/docs/operations.md:62-71`）。因此，若系统确实要在 undefined 时允许，正确做法是在策略中显式声明并评审 `default ... := true`，或在 PEP 中实现显式、可审计的 fail-open 分支；不能通过“读不到结果就默认放行”的隐式代码完成。

## 7. 参考的仓库位置

- `v1/rego/resultset.go:9-11`：空 `ResultSet` 表示 undefined query。
- `v1/rego/rego.go:2362-2440`：构造 topdown 查询并在无结果时返回 `nil, nil`。
- `v1/topdown/query.go:558-628`：`Query.Iter` 真实求值入口。
- `v1/topdown/eval.go:512-557`：表达式、等式/统一和裸表达式求值分支。
- `v1/topdown/eval.go:4166-4233`：完整规则的常规规则、`else`、default、undefined 缓存顺序。
- `v1/topdown/eval.go:2624-2677`：函数规则的相同回退顺序。
- `v1/topdown/eval.go:4947-4972`：`not` 将“子目标未定义”转换为成功。
- `v1/ast/index.go:44-51`：`IndexResult` 中 `Rules`、`Else`、`Default` 的结构。
- `v1/server/server.go:1846-1908`：Data API 执行与空结果响应。
- `v1/server/types/types.go:324-330`：`result,omitempty`，undefined 时 HTTP 响应为 `{}`。
- `docs/docs/policy-language.md:2068-2150`：default 与 default 函数参数 undefined 的语义。
- `docs/docs/policy-language.md:2157-2233`：`else` 有序回退语义。
- `docs/docs/kubernetes/primer.md:32-36`：admission deny 集合及规则顺序不改变结果。
- `docs/docs/operations.md:62-71`：执行点自行负责 fail-open/fail-closed。

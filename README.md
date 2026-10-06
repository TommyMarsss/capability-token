# capability-token

基于能力（Capability）的访问控制与令牌委托系统。根令牌可派生出权限更窄的子令牌，支持多级委托、签名链递归校验与撤销传播。仅使用 Go 标准库（`crypto/hmac`、`crypto/sha256`），无第三方依赖。

## 令牌结构

```go
type Token struct {
    ID           string    // 全局唯一标识
    ParentID     string    // 父令牌 ID，根令牌为空
    Issuer       string    // 签发者（委托方）
    Subject      string    // 持有者（被委托方）
    Capabilities []string  // 能力集合，如 "read:/data"
    NotBefore    time.Time // 生效时间
    ExpiresAt    time.Time // 过期时间
    Signature    []byte    // HMAC-SHA256 链式签名
}
```

### 链式签名（类似 Macaroon）

- 根令牌：`sig = HMAC-SHA256(rootSecret, canonical(token))`
- 子令牌：`sig = HMAC-SHA256(parent.Signature, canonical(token))`

`canonical(token)` 是令牌（不含签名）的规范 JSON 编码，能力列表排序后序列化，保证编码唯一。验证时从根向下重算整条链：任一环签名不匹配，整链失效。由于每环密钥就是上一环的签名，篡改链中任意一个令牌（改能力、换父节点、伪造签名）都会使其自身及全部下游校验失败。

## 委托的收敛约束（Attenuation）

派生子令牌时**签发即强制收敛**，以下请求会被拒绝：

| 约束 | 违反时的错误 |
|---|---|
| 子令牌能力 ⊆ 父令牌能力 | `ErrPrivilegeEscalation` |
| 子令牌过期时间 ≤ 父令牌过期时间 | `ErrExpiryExtension` |
| 子令牌生效时间 ≥ 父令牌生效时间 | `ErrNotBeforeTooEarly` |
| 父令牌当前必须可用（未撤销/未过期/链完整） | `ErrParentInvalid` |

验证（`Verify`）时会在链上每一环重新检查这些约束，因此即使攻击者绕过签发接口伪造令牌入库，也无法通过校验。

## 撤销传播算法

撤销采用**祖先标记 + 验证时沿链检查**，无需逐个点名后代：

1. `Revoke(id)` 只把 `id` 加入撤销集合，O(1)。
2. `Verify(id)` 先取从根到 `id` 的完整路径（`pathToRoot`），沿路径逐环检查：
   撤销集合命中 → 签名重算比对 → 收敛约束 → 时间有效性。
3. 由于路径包含全部祖先，任一祖先被撤销，后代 `Verify` 立即返回 `ErrRevoked`——撤销自然沿委托树向下传播，且只影响被撤销节点的子树，其他分支不受影响。

```
撤销 svcA 后：
root ✓
├── svcA ✗(被撤销)
│   ├── userA1 ✗(传播)
│   └── userA2 ✗(传播)
│       └── sessA2 ✗(传播)
└── svcB ✓（不受影响）
    └── userB1 ✓（不受影响）
```

`Descendants(id)` 用递归 DFS 枚举全部后代（先序），用于演示与测试中核对传播范围，复杂度 O(子树大小)。

## 运行测试

```sh
go test ./... -v
```

覆盖场景：

- 权限扩大 / 有效期延长 / 生效时间提前的派生请求被拒绝
- 合法多级委托链校验通过
- 篡改中间节点能力、伪造签名、换父重挂 → 整链校验失败
- 撤销中间节点 → 多级后代全部失效，其他分支不受影响
- 撤销根令牌 → 整棵树失效
- 已撤销令牌不允许再派生；过期令牌校验失败

## 静态演示页

`index.html` 是单一静态文件（数据与逻辑全部内嵌，无需启动任何服务），树形展示委托链：点击任意令牌即可撤销/恢复，被撤销的令牌标红，受传播影响的全部后代标橙，其他分支保持绿色。直接用浏览器打开即可。

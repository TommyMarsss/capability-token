# 能力令牌委托系统（Capability Token Delegation）

用 Go 标准库（`crypto/ed25519`）实现的基于能力（Capability）的访问控制与
**多级令牌委托**系统，重点验证两件事：

1. **委托单调收窄**：子令牌的能力必须是父令牌的子集、过期时间不得晚于父令牌；
2. **撤销沿树递归传播**：撤销任意令牌，其全部后代立即失效，但其他分支不受影响。

只依赖 Go 标准库；配套可视化是一个**单一静态 HTML 文件**（数据与逻辑全部内嵌，
不启动任何服务）。

## 快速开始

```bash
go test -race ./...          # 运行全部自动化测试

go run ./cmd/demo            # 生成 report.html（已在 .gitignore 中忽略）
open report.html             # 直接用浏览器打开，无需服务器
```

`cmd/demo` 会构造一棵多级委托树、撤销一个中间节点，并把三个“被拒绝的委托请求”
（权限扩大 ×2、有效期延长 ×1）一起渲染进页面。

## 代码结构

| 文件 | 职责 |
| --- | --- |
| `capability.go` | 能力集合：规范化、`IsSubsetOf` 子集判定 |
| `token.go` | 令牌结构、Ed25519 签名 / 解析 / 原语验签 |
| `authority.go` | 根签发、委托约束、递归链校验、撤销、快照导出 |
| `sort.go` | 快照节点排序（父先于子） |
| `cmd/demo/` | 演示场景 + 内嵌模板的静态页面生成器 |
| `*_test.go` | 委托约束、链篡改、撤销传播、过期、并发测试 |

## 令牌结构

紧凑字符串形式，类似 JWT 但**零第三方依赖**：

```
base64url(header).base64url(payload).base64url(signature)
```

**Header**

```json
{ "alg": "EdDSA", "kid": "<签名方公钥指纹>" }
```

**Payload（Claims）**

```json
{
  "tid":  "<本令牌公钥指纹，即 TokenID>",
  "pid":  "<父令牌 TokenID；根令牌省略>",
  "iss":  "持有者/角色名称",
  "caps": ["doc:read", "doc:write"],
  "iat":  1780650000,
  "exp":  1780650000
}
```

**签名规则**

- 签名内容固定为 ASCII 字节串 `header.payload`（两段 Base64URL，中间一个 `.`）。
- **根令牌自签名**：`kid == tid`，用根私钥签自己。
- **子令牌由父私钥签发**：header 中的 `kid` 是**父令牌**公钥指纹（即父 `tid`），
  从而链路上“谁签的我”无需额外数据即可定位。
- 每个令牌在签发时生成自己的独立 Ed25519 密钥对；它再用自己的私钥签发下一级。
- 能力集合在签名前经过排序去重（`json.Marshal` 输出确定），保证签名与验签的
  字节序列完全一致。

## 委托约束（签发时拒绝收窄以外的一切请求）

`Authority.Delegate(parent, issuer, caps, exp)` 在持锁状态下校验：

1. 父令牌存在、未撤销、未过期；
2. `NewCapabilities(caps…).IsSubsetOf(parent.caps)` —— 能力只能缩小或相等，
   新增任何父令牌没有的能力返回 `ErrCapabilityEscalation`；
3. `child.exp <= parent.exp` —— 有效期只能缩短或相等，
   返回 `ErrExpiryExtended`；
4. `child.exp > now` —— 不允许签发即过期的令牌。

## 验证：递归校验整条签名链

`Verify(raw)` 从被验令牌沿 `pid` 边**递归到根**，每个节点检查：

1. 节点存在于注册表、未撤销；
2. 未过期（`now < exp`，到点即失效）；
3. 签名密码学有效：
   - 根：用其自身公钥验签，且 `kid == tid`；
   - 子节点：`kid` 必须等于父 `tid`，并用**父公钥**做 Ed25519 验签；
4. 用注册表中**签发时存证的声明**复核 `caps ⊆ parent.caps` 与 `exp ≤ parent.exp`
   （不信任令牌自带的字节，防止绕过签发路径伪造）。

任意一环签名无效或约束被违反，立即返回对应错误，整个令牌不可用。

## 撤销传播算法

撤销是**惰性派生**的：撤销操作只对单个节点打一个标记位，不维护、不遍历任何
后代列表；“后代是否失效”在每次 `Verify` 时沿父链实时推导。

```
Revoke(X):
    record[X].revoked  = true
    record[X].revokedAt = now

Verify(X):                      validateChain(X):
    validateChain(X)              1. revoked[X]?        → ErrTokenRevoked
                                  2. expired[X]?        → ErrTokenExpired
                                  3. Ed25519 验签通过?   → ErrBadSignature
                                  4. 约束相对父节点成立?  → escalation/expiry
                                  5. 递归 validateChain(parent(X))
                                     根（pid 为空）验自签名后终止
```

**正确性论证**

- **完备性（后代一定失效）**：设 D 是 X 的任意后代。委托关系构成以根为终点的
  父指针链，X 位于 D 到根的唯一路径上。`validateChain(D)` 必经过 X，而
  `revoked[X] == true`，故 D 返回 `ErrTokenRevoked`。
- **独立性（旁支不受影响）**：委托树是一棵树（除根外每节点恰好一个父）。
  不在 X 子树内的令牌，其到根路径不经过 X，链上没有任何节点被置位，验证继续
  走签名与约束检查，结果与撤销前一致。
- **即时性**：标记与读取受同一把读写锁保护，撤销提交后的下一次验证即可见，
  无宽限期、无需等待传播。
- **O(链深)**：单次验证只访问从令牌到根的一条路径；撤销本身 O(1)。
  前端快照则一次性计算每个节点的最近被撤销祖先，用于高亮整条分支。

`Snapshot()` 把节点分为四态供页面着色：`valid` / `revoked`（撤销源头）/
`blocked_revoked`（祖先被撤销而连带失效）/ `expired`。

## 测试覆盖

| 测试 | 验证内容 |
| --- | --- |
| `TestCapabilitiesSubset` | 集合规范化与子集语义 |
| `TestValidMultilevelChain` | 四级链递归验签全部通过 |
| `TestDelegateRejectsCapabilityEscalation` / `TestRootCapsAreTheCeiling` | 新增能力、跨命名空间提权被拒 |
| `TestDelegateRejectsExpiryExtension` | 超出父级/祖父级有效期、过期签发被拒 |
| `TestDelegateAllowsEqualBounds` | 相等能力与相等有效期是合法的（子集与 `<=` 边界） |
| `TestSignParseVerifySignature` | Ed25519 原语：仅签名公钥可验签，改一个签名字节即失败 |
| `TestTamperedPayloadRejected` | 篡改 payload 加权限 / 改 `pid` 换父 → 整链 `ErrBadSignature` |
| `TestTamperedSignatureOrHeaderRejected` | 翻转签名/头部字节、畸形串、改写后串均被拒 |
| `TestRevocationPropagatesDownOnly` | 撤销 bob 后 bob/carol/dave/erin 全失效，root/alice/frank/grace/heidi 仍有效 |
| `TestRevocationIsImmediate` | 撤销后无需推进时钟立即失效 |
| `TestRevokeRootKillsEverything` | 撤销根使全树失效 |
| `TestRevokedTokenCannotDelegate` | 不能从已撤销令牌继续委托；不能撤销未知 id |
| `TestSnapshotClassification` | 快照四态分类与 `Verify` 结论一致 |
| `TestExpiry` | 到点失效、祖先过期语义 |
| `TestAuthorityConcurrentAccess` | `-race` 下并发签发 / 验证 / 撤销无数据竞争 |

## 设计说明与边界

- 示例中的 `Authority` 同时托管全部私钥，仅为单进程演示；真实部署中私钥由
  各方自持，注册表只需保存公钥与撤销位，验证算法不变。
- 撤销信息保存在内存中（进程重启丢失）。生产化可把 `record` 的 `revoked`
  位换成持久化/CRL/版本号存储；链验证逻辑无需改动。
- 时间由可注入的时钟函数提供，方便确定性测试。

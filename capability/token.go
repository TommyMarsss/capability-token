// Package capability 实现基于能力（Capability）的访问控制令牌，
// 支持根令牌派生权限更窄的子令牌、多级委托、签名链递归校验与撤销传播。
//
// 设计要点（类似 Macaroon 的链式 HMAC）：
//   - 根令牌用根密钥签名：sig = HMAC(rootSecret, canonical(token))
//   - 子令牌用父令牌的签名作为密钥：sig = HMAC(parent.Sig, canonical(token))
//   - 验证时从根向下重算整条签名链，任何一环不匹配即整链失效
//   - 派生时强制收敛：子令牌能力 ⊆ 父令牌能力，且有效期不晚于父令牌
package capability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

var (
	// ErrPrivilegeEscalation 子令牌请求了父令牌不具备的能力
	ErrPrivilegeEscalation = errors.New("capability: 子令牌能力超出父令牌范围（权限扩大被拒绝）")
	// ErrExpiryExtension 子令牌有效期晚于父令牌
	ErrExpiryExtension = errors.New("capability: 子令牌有效期超过父令牌（延长有效期被拒绝）")
	// ErrNotBeforeTooEarly 子令牌生效时间早于父令牌
	ErrNotBeforeTooEarly = errors.New("capability: 子令牌生效时间早于父令牌")
	// ErrTokenNotFound 令牌不存在
	ErrTokenNotFound = errors.New("capability: 令牌不存在")
	// ErrParentInvalid 父令牌当前不可用（已撤销、过期或签名链损坏）
	ErrParentInvalid = errors.New("capability: 父令牌不可用，无法派生")
	// ErrRevoked 令牌或其祖先已被撤销
	ErrRevoked = errors.New("capability: 令牌已被撤销（含撤销传播）")
	// ErrBadSignature 签名链中某一环签名无效
	ErrBadSignature = errors.New("capability: 签名链校验失败")
	// ErrConstraintBroken 链上某一环违反了收敛约束（能力/有效期）
	ErrConstraintBroken = errors.New("capability: 委托链收敛约束被违反")
	// ErrExpired 令牌已过期或尚未生效
	ErrExpired = errors.New("capability: 令牌已过期或尚未生效")
)

// Token 能力令牌。Signature 由 Store 计算，外部不应手工构造。
type Token struct {
	ID           string    `json:"id"`
	ParentID     string    `json:"parent_id"` // 根令牌为空
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	Capabilities []string  `json:"capabilities"` // 如 "read:/data", "write:/data"
	NotBefore    time.Time `json:"not_before"`
	ExpiresAt    time.Time `json:"expires_at"`
	Signature    []byte    `json:"signature"`
}

// canonical 返回令牌（不含签名）的规范编码，作为 HMAC 的消息。
// 能力列表排序后编码，保证同一令牌编码唯一。
func (t *Token) canonical() []byte {
	caps := make([]string, len(t.Capabilities))
	copy(caps, t.Capabilities)
	sort.Strings(caps)
	payload := struct {
		ID           string    `json:"id"`
		ParentID     string    `json:"parent_id"`
		Issuer       string    `json:"issuer"`
		Subject      string    `json:"subject"`
		Capabilities []string  `json:"capabilities"`
		NotBefore    time.Time `json:"not_before"`
		ExpiresAt    time.Time `json:"expires_at"`
	}{t.ID, t.ParentID, t.Issuer, t.Subject, caps, t.NotBefore, t.ExpiresAt}
	b, err := json.Marshal(payload)
	if err != nil {
		panic(err) // 字段全部可序列化，不会发生
	}
	return b
}

// Store 保存令牌、委托关系与撤销集合，负责签发、派生、校验与撤销。
type Store struct {
	rootSecret []byte
	tokens     map[string]*Token
	children   map[string][]string // parentID -> childIDs
	revoked    map[string]bool
	now        func() time.Time // 可注入时钟，便于测试
}

// NewStore 创建令牌仓库。rootSecret 是根令牌的签名密钥，必须保密。
func NewStore(rootSecret []byte) *Store {
	return &Store{
		rootSecret: rootSecret,
		tokens:     make(map[string]*Token),
		children:   make(map[string][]string),
		revoked:    make(map[string]bool),
		now:        time.Now,
	}
}

// SetClock 注入时钟（测试用）。
func (s *Store) SetClock(now func() time.Time) { s.now = now }

func sign(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// MintRoot 签发根令牌。根令牌拥有完整能力集合，是委托链的起点。
func (s *Store) MintRoot(id, issuer, subject string, caps []string, notBefore, expiresAt time.Time) (*Token, error) {
	if _, exists := s.tokens[id]; exists {
		return nil, fmt.Errorf("capability: 令牌 ID %q 已存在", id)
	}
	t := &Token{
		ID:           id,
		ParentID:     "",
		Issuer:       issuer,
		Subject:      subject,
		Capabilities: append([]string(nil), caps...),
		NotBefore:    notBefore,
		ExpiresAt:    expiresAt,
	}
	t.Signature = sign(s.rootSecret, t.canonical())
	s.tokens[id] = t
	return t, nil
}

// isSubset 判断 a 是否为 b 的子集。
func isSubset(a, b []string) bool {
	set := make(map[string]struct{}, len(b))
	for _, x := range b {
		set[x] = struct{}{}
	}
	for _, x := range a {
		if _, ok := set[x]; !ok {
			return false
		}
	}
	return true
}

// checkAttenuation 校验子令牌相对父令牌的收敛约束。
func checkAttenuation(parent, child *Token) error {
	if !isSubset(child.Capabilities, parent.Capabilities) {
		return ErrPrivilegeEscalation
	}
	if child.ExpiresAt.After(parent.ExpiresAt) {
		return ErrExpiryExtension
	}
	if child.NotBefore.Before(parent.NotBefore) {
		return ErrNotBeforeTooEarly
	}
	return nil
}

// Derive 从父令牌派生子令牌。签发时强制收敛：
// 能力必须是父令牌的子集，有效期不得超出父令牌，否则拒绝签发。
func (s *Store) Derive(parentID, id, subject string, caps []string, notBefore, expiresAt time.Time) (*Token, error) {
	parent, ok := s.tokens[parentID]
	if !ok {
		return nil, ErrTokenNotFound
	}
	if _, exists := s.tokens[id]; exists {
		return nil, fmt.Errorf("capability: 令牌 ID %q 已存在", id)
	}
	// 父令牌必须当前可用，否则不允许继续委托
	if err := s.Verify(parentID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParentInvalid, err)
	}
	child := &Token{
		ID:           id,
		ParentID:     parentID,
		Issuer:       parent.Subject, // 委托方即父令牌持有者
		Subject:      subject,
		Capabilities: append([]string(nil), caps...),
		NotBefore:    notBefore,
		ExpiresAt:    expiresAt,
	}
	if err := checkAttenuation(parent, child); err != nil {
		return nil, err
	}
	// 链式签名：以父令牌签名为密钥
	child.Signature = sign(parent.Signature, child.canonical())
	s.tokens[id] = child
	s.children[parentID] = append(s.children[parentID], id)
	return child, nil
}

// pathToRoot 返回从根到指定令牌的链（含两端）。
func (s *Store) pathToRoot(id string) ([]*Token, error) {
	var rev []*Token
	cur := id
	for {
		t, ok := s.tokens[cur]
		if !ok {
			return nil, ErrTokenNotFound
		}
		rev = append(rev, t)
		if t.ParentID == "" {
			break
		}
		cur = t.ParentID
		if len(rev) > len(s.tokens) { // 防御：父指针成环
			return nil, fmt.Errorf("capability: 委托链存在环")
		}
	}
	// 反转为 根 -> ... -> 目标
	path := make([]*Token, len(rev))
	for i, t := range rev {
		path[len(rev)-1-i] = t
	}
	return path, nil
}

// Verify 递归校验令牌的整条签名链直到根令牌。
// 链上任一环签名无效、约束被违反、被撤销或过期，整个令牌不可用。
func (s *Store) Verify(id string) error {
	path, err := s.pathToRoot(id)
	if err != nil {
		return err
	}
	now := s.now()
	prevKey := s.rootSecret
	var prev *Token
	for _, t := range path {
		// 1. 撤销检查（撤销传播：祖先被撤销则后代全部失效）
		if s.revoked[t.ID] {
			return fmt.Errorf("%w: %s", ErrRevoked, t.ID)
		}
		// 2. 重算签名并与存储值比对
		expected := sign(prevKey, t.canonical())
		if !hmac.Equal(expected, t.Signature) {
			return fmt.Errorf("%w: 令牌 %s 签名不匹配", ErrBadSignature, t.ID)
		}
		// 3. 链上收敛约束（防御被篡改后重新上链的令牌）
		if prev != nil {
			if err := checkAttenuation(prev, t); err != nil {
				return fmt.Errorf("%w: %v", ErrConstraintBroken, err)
			}
		}
		// 4. 时间有效性
		if now.Before(t.NotBefore) || now.After(t.ExpiresAt) {
			return fmt.Errorf("%w: %s", ErrExpired, t.ID)
		}
		prevKey = t.Signature
		prev = t
	}
	return nil
}

// Revoke 撤销令牌。其全部后代（递归）立即失效——
// 失效通过 Verify 中的祖先撤销检查传播，无需逐个标记。
func (s *Store) Revoke(id string) error {
	if _, ok := s.tokens[id]; !ok {
		return ErrTokenNotFound
	}
	s.revoked[id] = true
	return nil
}

// IsRevoked 报告令牌是否被直接撤销。
func (s *Store) IsRevoked(id string) bool { return s.revoked[id] }

// Descendants 返回令牌的全部后代 ID（递归，先序）。
func (s *Store) Descendants(id string) []string {
	var out []string
	var walk func(string)
	walk = func(pid string) {
		for _, c := range s.children[pid] {
			out = append(out, c)
			walk(c)
		}
	}
	walk(id)
	return out
}

// Get 返回令牌副本（只读用途）。
func (s *Store) Get(id string) (*Token, bool) {
	t, ok := s.tokens[id]
	if !ok {
		return nil, false
	}
	cp := *t
	return &cp, true
}

// Children 返回某令牌的直接子令牌 ID。
func (s *Store) Children(id string) []string {
	return append([]string(nil), s.children[id]...)
}

package capability

import (
	"errors"
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 = t0.Add(1 * time.Hour)
	t2 = t0.Add(2 * time.Hour)
	t3 = t0.Add(3 * time.Hour)
)

func newTestStore() *Store {
	s := NewStore([]byte("root-secret-for-tests"))
	s.SetClock(func() time.Time { return t1 }) // 所有令牌在 t1 时刻均有效
	return s
}

// buildTree 构造如下委托树：
//
//	root(read,write,delete; 0~3h)
//	├── svcA(read,write; 0~2h)
//	│   ├── userA1(read; 0~2h)
//	│   └── userA2(read,write; 0~1h)
//	│       └── sessA2(read; 0~1h)
//	└── svcB(read; 0~3h)
//	    └── userB1(read; 0~2h)
func buildTree(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.MintRoot("root", "admin", "svc-mesh",
		[]string{"read:/data", "write:/data", "delete:/data"}, t0, t3); err != nil {
		t.Fatalf("MintRoot: %v", err)
	}
	if _, err := s.Derive("root", "svcA", "service-a",
		[]string{"read:/data", "write:/data"}, t0, t2); err != nil {
		t.Fatalf("Derive svcA: %v", err)
	}
	if _, err := s.Derive("svcA", "userA1", "user-alice",
		[]string{"read:/data"}, t0, t2); err != nil {
		t.Fatalf("Derive userA1: %v", err)
	}
	if _, err := s.Derive("svcA", "userA2", "user-bob",
		[]string{"read:/data", "write:/data"}, t0, t1); err != nil {
		t.Fatalf("Derive userA2: %v", err)
	}
	if _, err := s.Derive("userA2", "sessA2", "session-bob-1",
		[]string{"read:/data"}, t0, t1); err != nil {
		t.Fatalf("Derive sessA2: %v", err)
	}
	if _, err := s.Derive("root", "svcB", "service-b",
		[]string{"read:/data"}, t0, t3); err != nil {
		t.Fatalf("Derive svcB: %v", err)
	}
	if _, err := s.Derive("svcB", "userB1", "user-carol",
		[]string{"read:/data"}, t0, t2); err != nil {
		t.Fatalf("Derive userB1: %v", err)
	}
}

// 1. 权限扩大请求必须被拒绝
func TestDeriveRejectsPrivilegeEscalation(t *testing.T) {
	s := newTestStore()
	if _, err := s.MintRoot("root", "admin", "svc",
		[]string{"read:/data"}, t0, t3); err != nil {
		t.Fatal(err)
	}
	// 子令牌请求父令牌没有的写权限
	_, err := s.Derive("root", "child", "attacker",
		[]string{"read:/data", "write:/data"}, t0, t2)
	if !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("期望 ErrPrivilegeEscalation，得到 %v", err)
	}
	// 被拒绝的令牌不应入库
	if _, ok := s.Get("child"); ok {
		t.Fatal("被拒绝的令牌不应写入仓库")
	}
}

// 2. 有效期延长请求必须被拒绝
func TestDeriveRejectsExpiryExtension(t *testing.T) {
	s := newTestStore()
	if _, err := s.MintRoot("root", "admin", "svc",
		[]string{"read:/data"}, t0, t2); err != nil {
		t.Fatal(err)
	}
	_, err := s.Derive("root", "child", "attacker",
		[]string{"read:/data"}, t0, t3) // 过期时间晚于父令牌
	if !errors.Is(err, ErrExpiryExtension) {
		t.Fatalf("期望 ErrExpiryExtension，得到 %v", err)
	}
	// 生效时间早于父令牌同样拒绝
	if _, err = s.Derive("root", "child2", "attacker",
		[]string{"read:/data"}, t0.Add(-time.Hour), t1); !errors.Is(err, ErrNotBeforeTooEarly) {
		t.Fatalf("期望 ErrNotBeforeTooEarly，得到 %v", err)
	}
}

// 3. 合法多级委托链校验通过
func TestVerifyValidChain(t *testing.T) {
	s := newTestStore()
	buildTree(t, s)
	for _, id := range []string{"root", "svcA", "userA1", "userA2", "sessA2", "svcB", "userB1"} {
		if err := s.Verify(id); err != nil {
			t.Fatalf("Verify(%s) 应通过，得到 %v", id, err)
		}
	}
}

// 4. 签名链被篡改导致整链校验失败
func TestTamperedChainFailsVerification(t *testing.T) {
	t.Run("篡改中间节点能力", func(t *testing.T) {
		s := newTestStore()
		buildTree(t, s)
		// 攻击者直接改写仓库中 svcA 的能力（伪造权限），但不重算签名
		s.tokens["svcA"].Capabilities = append(s.tokens["svcA"].Capabilities, "delete:/data")
		// svcA 本身失效
		if err := s.Verify("svcA"); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("svcA 应签名校验失败，得到 %v", err)
		}
		// 其下游所有后代也整链失效
		for _, id := range []string{"userA1", "userA2", "sessA2"} {
			if err := s.Verify(id); err == nil {
				t.Fatalf("中间节点被篡改后，后代 %s 必须失效", id)
			}
		}
		// 未受影响的分支仍然有效
		if err := s.Verify("userB1"); err != nil {
			t.Fatalf("无关分支 userB1 不应受影响，得到 %v", err)
		}
	})

	t.Run("伪造签名", func(t *testing.T) {
		s := newTestStore()
		buildTree(t, s)
		// 翻转签名的一个字节
		s.tokens["userA1"].Signature[0] ^= 0xff
		if err := s.Verify("userA1"); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("签名被篡改后应校验失败，得到 %v", err)
		}
	})

	t.Run("换父重挂", func(t *testing.T) {
		s := newTestStore()
		buildTree(t, s)
		// 攻击者把 sessA2 挂到 svcB 下企图改变链（签名不变）
		s.tokens["sessA2"].ParentID = "svcB"
		if err := s.Verify("sessA2"); err == nil {
			t.Fatal("换父后签名链必须校验失败")
		}
	})
}

// 5. 撤销传播：撤销中间节点，多级后代全部失效，其他分支不受影响
func TestRevocationPropagatesToAllDescendants(t *testing.T) {
	s := newTestStore()
	buildTree(t, s)

	if err := s.Revoke("svcA"); err != nil {
		t.Fatal(err)
	}

	// svcA 及其全部后代（含多级）立即失效
	for _, id := range []string{"svcA", "userA1", "userA2", "sessA2"} {
		if err := s.Verify(id); !errors.Is(err, ErrRevoked) {
			t.Fatalf("撤销传播后 %s 应失效(ErrRevoked)，得到 %v", id, err)
		}
	}
	// 其他分支与根不受影响
	for _, id := range []string{"root", "svcB", "userB1"} {
		if err := s.Verify(id); err != nil {
			t.Fatalf("未撤销分支 %s 应保持有效，得到 %v", id, err)
		}
	}
	// Descendants 应枚举全部后代
	desc := s.Descendants("svcA")
	if len(desc) != 3 {
		t.Fatalf("svcA 应有 3 个后代，得到 %v", desc)
	}
}

// 6. 撤销根令牌：整棵树失效
func TestRevokeRootInvalidatesEverything(t *testing.T) {
	s := newTestStore()
	buildTree(t, s)
	if err := s.Revoke("root"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"root", "svcA", "userA1", "userA2", "sessA2", "svcB", "userB1"} {
		if err := s.Verify(id); !errors.Is(err, ErrRevoked) {
			t.Fatalf("根被撤销后 %s 应失效，得到 %v", id, err)
		}
	}
}

// 7. 已撤销的令牌不允许再派生
func TestCannotDeriveFromRevokedToken(t *testing.T) {
	s := newTestStore()
	buildTree(t, s)
	if err := s.Revoke("svcA"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Derive("svcA", "sneaky", "attacker", []string{"read:/data"}, t0, t1)
	if !errors.Is(err, ErrParentInvalid) {
		t.Fatalf("从已撤销令牌派生应被拒绝，得到 %v", err)
	}
}

// 8. 过期令牌校验失败
func TestExpiredTokenFails(t *testing.T) {
	s := newTestStore()
	buildTree(t, s)
	s.SetClock(func() time.Time { return t3.Add(time.Hour) }) // 全部过期
	if err := s.Verify("root"); !errors.Is(err, ErrExpired) {
		t.Fatalf("过期后应校验失败，得到 %v", err)
	}
}

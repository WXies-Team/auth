package auth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// 号段口径：1,000,000 ~ 9,999,999——恒为 7 位，上下界都是硬要求（下界卡位数，
// 上界卡「不出 8 位号」），跑满 500 次也不许出一个界外值。
func TestRandUserIDRange(t *testing.T) {
	seen := map[int64]bool{}
	for i := 0; i < 500; i++ {
		id, err := randUserID()
		if err != nil {
			t.Fatalf("取号失败: %v", err)
		}
		if id < uidMin || id > uidMax {
			t.Fatalf("uid %d 越界（应落在 %d~%d）", id, uidMin, uidMax)
		}
		if id < 1000000 || id > 9999999 {
			t.Errorf("uid %d 不是 7 位", id)
		}
		seen[id] = true
	}
	// 随机性烟雾测试：500 次取号若只有个位数去重值，说明号源退化成了常量/小集合
	if len(seen) < 480 {
		t.Errorf("500 次取号只有 %d 个不同值——号源不随机", len(seen))
	}
}

// 撞已有行 → 换号重试成功（真库）：号源先吐一个**库里已存在**的 id，insert 必吃
// 主键 1062，newUserID 应换号再插，最终落库的是另一个 7 位号。
func TestNewUserIDRetriesOnTakenRow(t *testing.T) {
	svc, _ := newTestService(t)
	const taken = int64(1234567)
	insRow := func(id int64, email string) error {
		_, err := svc.pool.Exec(
			"INSERT INTO users (id, email, password_hash, created_at, token_version) VALUES (?,?,NULL,?,1)",
			id, email, time.Now().UnixMilli())
		return err
	}
	if err := insRow(taken, "taken@example.com"); err != nil {
		t.Fatalf("铺垫已存在行: %v", err)
	}

	first := true
	gen := func() (int64, error) {
		if first {
			first = false
			return taken, nil // 首个候选号故意撞库里的行
		}
		return randUserID()
	}
	got, err := newUserID(gen, func(id int64) error {
		return insRow(id, fmt.Sprintf("uid-%d@example.com", id))
	})
	if err != nil {
		t.Fatalf("撞号后应换号重试成功: %v", err)
	}
	if got == taken {
		t.Errorf("撞过的号不该被回给调用方: %d", got)
	}
	if got < uidMin || got > uidMax {
		t.Errorf("重试得到的 uid %d 不在 %d~%d", got, uidMin, uidMax)
	}
	var n int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", got).Scan(&n); err != nil || n != 1 {
		t.Errorf("重试号应真的落库: n=%d err=%v", n, err)
	}
}

// 连撞 uidTries 次（每次都撞同一个已存在的号）必须报错返回，不许无限转圈。
func TestNewUserIDGivesUpAfterMaxTries(t *testing.T) {
	const taken = int64(1234567)
	calls := 0
	_, err := newUserID(
		func() (int64, error) { return taken, nil },
		func(id int64) error {
			calls++
			return &mysql.MySQLError{
				Number:  1062,
				Message: fmt.Sprintf("Duplicate entry '%d' for key 'users.PRIMARY'", id),
			}
		},
	)
	if err == nil {
		t.Fatal("连续撞号应报错")
	}
	if calls != uidTries {
		t.Errorf("应尝试 %d 次，得到 %d 次", uidTries, calls)
	}
	if !strings.Contains(err.Error(), "撞已有 uid") {
		t.Errorf("错误应说明撞号，得到: %v", err)
	}
}

// 非「号撞了」的错误一律原样上抛、只试一次——邮箱唯一键的 1062 若进重试循环，
// Register 会白转 10 次才把同一句「该邮箱已注册」吐出来；连接错更不该重试。
func TestNewUserIDStopsOnOtherErrors(t *testing.T) {
	cases := map[string]error{
		"邮箱唯一键 1062": &mysql.MySQLError{
			Number:  1062,
			Message: "Duplicate entry 'a@b.com' for key 'users.uq_users_email'",
		},
		"连接错": errors.New("driver: bad connection"),
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			_, err := newUserID(
				func() (int64, error) { return 1234567, nil },
				func(int64) error { calls++; return want },
			)
			if !errors.Is(err, want) {
				t.Errorf("应原样上抛 %v，得到 %v", want, err)
			}
			if calls != 1 {
				t.Errorf("非撞号错误不该重试，得到 %d 次", calls)
			}
		})
	}
}

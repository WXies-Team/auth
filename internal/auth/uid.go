package auth

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// users.id 的号段：**7 位随机整数**，1,000,000 ~ 9,999,999。
//
// 恒 7 位（下界卡 100 万，没有前导零也没有 6 位短号）、可口播可手输，且随机取号
// 同样不暴露注册顺序——自增 id 才会。App 未上线，存量雪花 uid 由
// scripts/migrate-uid-7digit.sh 一次性改写，零兼容包袱。
const (
	uidMin = 1000000
	uidMax = 9999999
	// uidTries 是撞号重试上限。号段 900 万个，账号数远在其下，连续撞 10 次
	// 在概率上只可能是取号源坏了——报错比无限重试诚实。
	uidTries = 10
)

// randUserID 从 crypto/rand 取 [uidMin, uidMax] 内的整数（恒 7 位）。
//
// 区间宽度 9,000,000 不是 2 的幂，裸取模会让低位值概率略高——用拒绝采样消偏置：
// 只接受 [0, 2^64 内 9,000,000 的整数倍) 里的值，这一段取模才均匀。
func randUserID() (int64, error) {
	const span = uint64(uidMax - uidMin + 1)
	limit := ^uint64(0) / span * span
	for {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("取随机 uid: %w", err)
		}
		if v := binary.LittleEndian.Uint64(b[:]); v < limit {
			return uidMin + int64(v%span), nil
		}
	}
}

// newUserID 造一个「insert 成功即落库」的 7 位 uid：gen 出候选号，insert 落 users 行。
//
// 撞号交给数据库判：候选撞 users 主键就换号重试，最多 uidTries 次。其它错误原样上抛
// ——邮箱唯一键的 1062 若也进重试，注册会白转 10 次再报同样的错，见 isDuplicateUID。
//
// gen / insert 由调用方注入：Register 与 EnsureUsers 各自把本事务里的 INSERT 传进来，
// 测试则喂固定号源来复现「先撞已有行、再拿到空号」的重试链路。
func newUserID(gen func() (int64, error), insert func(id int64) error) (int64, error) {
	var last error
	for try := 0; try < uidTries; try++ {
		id, err := gen()
		if err != nil {
			return 0, err
		}
		if err := insert(id); err != nil {
			if !isDuplicateUID(err, id) {
				return 0, err
			}
			last = err
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("连续 %d 次撞已有 uid: %w", uidTries, last)
}

// isDuplicateUID 判「这次候选号撞了 users 主键」：go-sql-driver 的 *mysql.MySQLError
// + 1062，且报错里的重复值就是本次候选号。
//
// 重复值这一条是必需的：uq_users_email 的冲突同样是 1062，它的重复值是邮箱串——
// 光看错误码分不出「号撞了」和「邮箱被占了」，而后者必须原样交给 Register 翻译成
//「该邮箱已注册」，重试换号毫无意义。
func isDuplicateUID(err error, id int64) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == 1062 &&
		strings.Contains(me.Message, fmt.Sprintf("Duplicate entry '%d'", id))
}

package auth

import (
	"sync"
	"time"
)

// attemptLimiter 是进程内的滑动窗口限流器：只记「失败尝试/请求」的时间点，
// 用于登录密码与邮箱验证码这类可被暴力枚举的入口。
//
// 单实例假设与 oauthStore 一致（当前部署就是一进程），不落库：重启后窗口清零是可接受的
// 代价，换来的是零 DB 写入——登录失败的路径本来就不该再打数据库。
type attemptLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
	swept  time.Time
}

func newAttemptLimiter(limit int, window time.Duration) *attemptLimiter {
	return &attemptLimiter{
		limit:  limit,
		window: window,
		hits:   make(map[string][]time.Time),
	}
}

// allow 记录一次尝试并返回是否放行；key 为空（拿不到 IP 等）时直接放行，
// 不让「取不到维度」变成全局拒绝。
func (l *attemptLimiter) allow(key string, now time.Time) bool {
	if key == "" || l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	// 每次窗口翻转清一遍过期键，防止攻击者用海量随机邮箱把 map 撑大
	if now.Sub(l.swept) > l.window {
		for k, v := range l.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > l.window {
				delete(l.hits, k)
			}
		}
		l.swept = now
	}

	cutoff := now.Add(-l.window)
	list := l.hits[key]
	i := 0
	for i < len(list) && !list[i].After(cutoff) {
		i++
	}
	list = list[i:]
	if len(list) >= l.limit {
		l.hits[key] = list
		return false
	}
	l.hits[key] = append(list, now)
	return true
}

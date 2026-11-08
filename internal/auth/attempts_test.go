package auth

import (
	"testing"
	"time"
)

func TestAttemptLimiterWindowAndKeys(t *testing.T) {
	l := newAttemptLimiter(3, time.Minute)
	start := time.Unix(1_700_000_000, 0)
	for i := 0; i < 3; i++ {
		if !l.allow("a", start.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("第 %d 次应放行", i+1)
		}
	}
	if l.allow("a", start.Add(4*time.Second)) {
		t.Fatal("超过窗口上限仍放行")
	}
	if !l.allow("b", start.Add(4*time.Second)) {
		t.Fatal("不同 key 不应互相影响")
	}
	if !l.allow("a", start.Add(2*time.Minute)) {
		t.Fatal("窗口外的旧记录应过期")
	}
	if !l.allow("", start) {
		t.Fatal("空 key（拿不到维度）应直接放行")
	}
}

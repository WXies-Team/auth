// Package config 读取应用级配置（MySQL 的 app_config 表）。
//
// 与热量日记服务同款：改库即热生效，热生效延迟 ≤10s——Get 走进程内短 TTL 缓存。
// P0 只有邮件三键（mail_tenant_id / mail_client_id / mail_client_secret）会走这里，
// 量级极小，缓存的意义是「改库立刻生效、又不为每个请求多打一次点查」。
//
// ⚠️ token_version **不缓存**：它在 users 表、由 auth 每请求现读——那是吊销
// （logout/改密 +1）的唯一机制，缓 10 秒等于吊销留 10 秒空窗。本包只碰 app_config。
//
// 键只在生产库里，仓库与本文件都不出现任何真实值。
package config

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"
)

// ErrNotFound 表示键不存在或值为空（空值当「没配」，与热量日记服务一致）。
var ErrNotFound = errors.New("配置键不存在")

// cacheTTL 是 app_config 的进程内缓存时长。改库是极低频操作，10 秒无感；
// 而发码/健康检查密集时省掉重复点查。
const cacheTTL = 10 * time.Second

// cachedValue 连「键不存在」也缓存（负缓存）：新配的键最多 10 秒后可见。
// **真错误不缓存**——DB 抖动被钉住 10 秒会把一次超时放大成 10 秒的持续故障。
type cachedValue struct {
	value string
	err   error
	at    time.Time
}

// Store 是 app_config 的读取器。
type Store struct {
	pool *sql.DB

	mu    sync.Mutex
	cache map[string]cachedValue
}

// New 返回一个读取器；nil pool 会让所有 Get 返回 ErrNotFound，
// 于是未接库的阶段也能安全启动。
func New(pool *sql.DB) *Store {
	return &Store{pool: pool, cache: map[string]cachedValue{}}
}

// Get 读一个键，返回**去掉首尾空白后**的值；键不存在或值为空都返回 ErrNotFound。
func (s *Store) Get(key string) (string, error) {
	if s == nil || s.pool == nil {
		return "", ErrNotFound
	}
	if v, err, ok := s.lookup(key); ok {
		return v, err
	}
	var raw string
	err := s.pool.QueryRow("SELECT `value` FROM app_config WHERE `key` = ?", key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		s.remember(key, "", ErrNotFound)
		return "", ErrNotFound
	}
	if err != nil {
		return "", err // 瞬时错误不进缓存
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		s.remember(key, "", ErrNotFound)
		return "", ErrNotFound
	}
	s.remember(key, trimmed, nil)
	return trimmed, nil
}

// lookup 命中且未过期才返回 ok=true；过期条目顺手删掉（键集合是代码里的常量，
// 不会无限增长）。
func (s *Store) lookup(key string) (string, error, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cache[key]
	if !ok {
		return "", nil, false
	}
	if time.Since(c.at) >= cacheTTL {
		delete(s.cache, key)
		return "", nil, false
	}
	return c.value, c.err, true
}

func (s *Store) remember(key, value string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[string]cachedValue{}
	}
	s.cache[key] = cachedValue{value: value, err: err, at: time.Now()}
}

// Require 同 Get，但键缺失返回 ("", nil)——适合「没配就跳过」的可选配置，
// 避免调用方把 ErrNotFound 当成真错误往上抛。
func (s *Store) Require(key string) (string, error) {
	v, err := s.Get(key)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	return v, err
}

// StringFunc 把 Store 适配成 mail 包的 ConfigFunc（取不到返回 ""）。
func (s *Store) StringFunc(key string) string {
	v, _ := s.Require(key)
	return v
}

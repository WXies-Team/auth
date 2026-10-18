<?php

namespace Tests\Support;

use Admin9\OidcServer\Contracts\AtomicStateStore;

/**
 * 内存版原子状态存储，供测试替代 Redis。
 *
 * 包的 RedisAtomicStateStore 在无 Redis 时 fail-closed，测试环境没有 Redis，
 * 绑定此替身即可跑通完整授权流。
 */
class ArrayAtomicStateStore implements AtomicStateStore
{
    /** @var array<string, array{value: string, expires: int}> */
    private array $store = [];

    public function create(string $key, string $value, int $seconds): bool
    {
        if (isset($this->store[$key])) {
            return false;
        }
        $this->store[$key] = ['value' => $value, 'expires' => time() + $seconds];

        return true;
    }

    public function read(string $key): ?string
    {
        $entry = $this->store[$key] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($entry['expires'] < time()) {
            unset($this->store[$key]);

            return null;
        }

        return $entry['value'];
    }

    public function replace(string $key, string $expected, string $value, int $seconds): bool
    {
        if ($this->read($key) !== $expected) {
            return false;
        }
        $this->store[$key] = ['value' => $value, 'expires' => time() + $seconds];

        return true;
    }
}

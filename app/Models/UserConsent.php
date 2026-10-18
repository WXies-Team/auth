<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * 记住授权：用户对某 client 同意过的 scope 集合。
 *
 * scope 存已同意的最大集合；后续请求为其子集时静默跳过同意屏。
 */
class UserConsent extends Model
{
    use HasFactory;

    protected $fillable = ['user_id', 'client_id', 'scopes'];

    protected function casts(): array
    {
        return ['scopes' => 'array'];
    }

    /**
     * 请求的 scope 是否已全部被同意过（子集即跳过同意屏）。
     *
     * @param  array<int, string>  $requested
     */
    public function covers(array $requested): bool
    {
        return array_diff($requested, $this->scopes ?? []) === [];
    }
}

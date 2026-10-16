<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * 用户的一台"已登录设备"（一条网关登录会话）。
 * 下线 = 删除本行 + 作废对应 Laravel session 行。
 */
class LoginSession extends Model
{
    public $timestamps = false;

    protected $fillable = [
        'user_id',
        'session_id',
        'ip',
        'user_agent',
        'last_active_at',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'last_active_at' => 'datetime',
            'created_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}

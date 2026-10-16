<?php

namespace App\Models;

use Database\Factories\IdentityFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * 外部身份链接（GitHub / Google 等）。网关只存身份标识，不存第三方业务数据。
 */
class Identity extends Model
{
    /** @use HasFactory<IdentityFactory> */
    use HasFactory;

    protected $fillable = [
        'user_id',
        'provider',
        'provider_user_id',
        'provider_email',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}

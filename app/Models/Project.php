<?php

namespace App\Models;

use Database\Factories\ProjectFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Laravel\Passport\Client;

/**
 * 接入网关的业务项目。项目是授权作用域：成员角色（admin/member）
 * 只在本项目生效；全局管理员（super_admin）对所有项目拥有管理权。
 */
class Project extends Model
{
    /** @use HasFactory<ProjectFactory> */
    use HasFactory;

    protected $fillable = [
        'slug',
        'name',
        'description',
        'created_by',
    ];

    /** @return BelongsToMany<User, $this> */
    public function members(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'project_members')->withPivot('role')->withTimestamps();
    }

    /** @return BelongsToMany<User, $this> */
    public function admins(): BelongsToMany
    {
        return $this->members()->wherePivot('role', 'admin');
    }

    /** @return HasMany<Client, $this> */
    public function clients(): HasMany
    {
        return $this->hasMany(Client::class);
    }

    /**
     * 用户在本项目中的角色（不含全局管理员的隐式放行）。
     */
    public function roleOf(User $user): ?string
    {
        return $this->members()
            ->whereKey($user->getKey())
            ->pivot('role')
            ->value('role');
    }
}

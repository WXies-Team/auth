<?php

namespace App\Policies;

use App\Models\Project;
use App\Models\User;

/**
 * 项目级授权：全局管理员放行；否则要求该项目 pivot 角色为 admin。
 * （Gate::before 已处理 super_admin，这里只写项目级规则。）
 */
class ProjectPolicy
{
    // 全局管理员放行由 AppServiceProvider 的 Gate::before 统一处理。

    public function view(User $user, Project $project): bool
    {
        return $project->roleOf($user) !== null;
    }

    public function update(User $user, Project $project): bool
    {
        return $project->roleOf($user) === 'admin';
    }

    public function manageMembers(User $user, Project $project): bool
    {
        return $project->roleOf($user) === 'admin';
    }

    public function manageClients(User $user, Project $project): bool
    {
        return $project->roleOf($user) === 'admin';
    }

    public function delete(User $user, Project $project): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * 创建项目仅全局管理员（普通用户经 before 的 null 落到这里返回 false）。
     */
    public function create(User $user): bool
    {
        return false;
    }
}

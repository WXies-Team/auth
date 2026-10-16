<?php

namespace App\Providers;

use Admin9\OidcServer\Contracts\ReauthenticationHandler;
use App\Authentication\HostReauthenticationHandler;
use App\Models\User;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Laravel\Passkeys\Contracts\PasskeyLoginResponse;
use Laravel\Passkeys\Passkeys;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // OIDC 授权流程中需要（重新）认证时，重定向到宿主登录页。
        $this->app->bind(ReauthenticationHandler::class, HostReauthenticationHandler::class);

        // Passkey 登录成功后补记认证时间并续跳 OIDC 事务（见类注释）。
        $this->app->singleton(
            PasskeyLoginResponse::class,
            \App\Http\Responses\PasskeyLoginResponse::class
        );
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Passkeys::useUserModel(User::class);

        // 全局管理员对一切资源放行（super_admin ≈ ZITADEL IAM_OWNER）。
        Gate::before(
            fn (User $user, string $ability): ?bool => $user->isSuperAdmin() ? true : null
        );

        // 进入管理后台的门槛：全局管理员，或至少是某个项目的成员。
        Gate::define(
            'access-admin',
            fn (User $user): bool => $user->isSuperAdmin()
                || $user->projects()->exists()
        );

        // 全局用户/角色管理仅限全局管理员。
        Gate::define(
            'manage-users',
            fn (User $user): bool => $user->isSuperAdmin()
        );
    }
}

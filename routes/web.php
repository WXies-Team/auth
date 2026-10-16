<?php

use App\Http\Controllers\Admin\DashboardController;
use App\Http\Controllers\Admin\ProjectClientController;
use App\Http\Controllers\Admin\ProjectController;
use App\Http\Controllers\Admin\ProjectMemberController;
use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\ReauthenticateController;
use App\Http\Controllers\Auth\SecurityController;
use App\Http\Controllers\Auth\SessionController;
use App\Http\Controllers\Auth\SocialAuthController;
use App\Http\Controllers\Auth\TwoFactorChallengeController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('home');
})->name('home');

// 登录与重认证路由必须启用会话阻塞（admin9/oidc-server 2.0 契约），
// POST 登录带限流；重认证页面对游客可达。
Route::middleware('web')->group(function (): void {
    Route::get('/login', [LoginController::class, 'show'])->name('login');
    Route::post('/login', [LoginController::class, 'store'])
        ->middleware('throttle:30,1')
        ->block();
    Route::post('/logout', [LoginController::class, 'destroy'])->name('logout')->middleware('throttle:10,1');

    Route::get('/reauthenticate', [ReauthenticateController::class, 'show'])
        ->block()
        ->name('auth.reauthenticate');
    Route::post('/reauthenticate', [ReauthenticateController::class, 'store'])
        ->middleware('throttle:30,1')
        ->block();

    Route::get('/two-factor', [TwoFactorChallengeController::class, 'show'])
        ->block()
        ->name('two-factor.show');
    Route::post('/two-factor', [TwoFactorChallengeController::class, 'store'])
        ->middleware('throttle:30,1')
        ->block()
        ->name('two-factor.store');

    // 社交登录（GitHub / Google）。回调不加 throttle：一次跳转一次请求，
    // 且 Socialite 自带 state 校验；入口限流由登录页承担。
    Route::get('/auth/{provider}', [SocialAuthController::class, 'redirectTo'])->name('social.redirect');
    Route::get('/auth/{provider}/callback', [SocialAuthController::class, 'callback'])->name('social.callback');

    // 账户安全设置（需登录）
    Route::middleware('auth')->prefix('settings')->group(function (): void {
        Route::get('/security', [SecurityController::class, 'show'])->name('security.show');
        Route::post('/security/two-factor', [SecurityController::class, 'enable'])
            ->middleware('throttle:10,1')
            ->name('security.two-factor.enable');
        Route::post('/security/two-factor/confirm', [SecurityController::class, 'confirm'])
            ->middleware('throttle:30,1')
            ->name('security.two-factor.confirm');
        Route::delete('/security/two-factor', [SecurityController::class, 'disable'])
            ->middleware('throttle:10,1')
            ->name('security.two-factor.disable');
        Route::post('/security/recovery-codes', [SecurityController::class, 'regenerateRecoveryCodes'])
            ->middleware('throttle:5,1')
            ->name('security.recovery-codes');

        // 已登录设备管理
        Route::get('/sessions', [SessionController::class, 'index'])->name('sessions.index');
        Route::delete('/sessions/{session}', [SessionController::class, 'destroy'])->name('sessions.destroy');
        Route::delete('/sessions', [SessionController::class, 'destroyOthers'])
            ->middleware('throttle:10,1')
            ->name('sessions.destroy-others');
    });

    // 管理后台：全局管理员或项目成员可进入；具体操作由 ProjectPolicy 细分。
    Route::middleware(['auth', 'can:access-admin'])->prefix('admin')->name('admin.')->group(function (): void {
        Route::get('/', DashboardController::class)->name('dashboard');

        Route::get('/projects/create', [ProjectController::class, 'create'])->name('projects.create');
        Route::post('/projects', [ProjectController::class, 'store'])
            ->middleware('throttle:10,1')
            ->name('projects.store');
        Route::get('/projects/{project}', [ProjectController::class, 'show'])->name('projects.show');
        Route::get('/projects/{project}/edit', [ProjectController::class, 'edit'])->name('projects.edit');
        Route::put('/projects/{project}', [ProjectController::class, 'update'])->name('projects.update');
        Route::delete('/projects/{project}', [ProjectController::class, 'destroy'])->name('projects.destroy');

        Route::post('/projects/{project}/members', [ProjectMemberController::class, 'store'])
            ->middleware('throttle:30,1')->name('projects.members.store');
        Route::put('/projects/{project}/members/{user}', [ProjectMemberController::class, 'update'])->name('projects.members.update');
        Route::delete('/projects/{project}/members/{user}', [ProjectMemberController::class, 'destroy'])->name('projects.members.destroy');

        Route::post('/projects/{project}/clients', [ProjectClientController::class, 'store'])
            ->middleware('throttle:30,1')->name('projects.clients.store');
        Route::post('/projects/{project}/clients/{client}/rotate', [ProjectClientController::class, 'rotateSecret'])->name('projects.clients.rotate');
        Route::delete('/projects/{project}/clients/{client}', [ProjectClientController::class, 'destroy'])->name('projects.clients.destroy');

        // 全局用户管理（仅全局管理员）。
        Route::middleware('can:manage-users')->group(function (): void {
            Route::get('/users', [UserController::class, 'index'])->name('users.index');
            Route::put('/users/{user}/role', [UserController::class, 'updateRole'])
                ->middleware('throttle:30,1')->name('users.role');
        });

        // 审计日志（仅全局管理员）
        Route::get('/audit', [\App\Http\Controllers\Admin\AuditController::class, 'index'])
            ->middleware('can:manage-users')
            ->name('audit.index');
    });
});

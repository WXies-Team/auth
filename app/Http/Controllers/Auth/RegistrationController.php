<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\AuditLogger;
use App\Services\LoginFinalizer;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rules\Password;
use Illuminate\View\View;

class RegistrationController extends Controller
{
    public function show(): View|RedirectResponse
    {
        if (! config('oidc.registration_enabled')) {
            abort(404);
        }

        return view('auth.register');
    }

    public function store(Request $request): RedirectResponse
    {
        abort_unless(config('oidc.registration_enabled'), 404);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:64'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'confirmed', Password::defaults()],
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            // User 模型有 password => hashed cast，赋明文即自动哈希。
            'password' => $data['password'],
            'email_verified_at' => now(),
        ]);

        app(AuditLogger::class)->record('user.registered', $user->getKey(), metadata: [
            'email' => $user->email,
        ]);

        // 注册即登录，复用统一收尾（设备跟踪 / 审计 / 会话轮换）。
        return app(LoginFinalizer::class)->finalize(
            $request,
            'web',
            $user,
            method: 'registration',
        );
    }
}

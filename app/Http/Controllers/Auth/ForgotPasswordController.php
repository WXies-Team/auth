<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Notifications\PasswordResetNotification;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\View\View;

class ForgotPasswordController extends Controller
{
    public function show(): View
    {
        return view('auth.forgot-password');
    }

    public function store(Request $request): RedirectResponse
    {
        $request->validate(['email' => ['required', 'email']]);

        // 无论账号是否存在都返回同一提示，避免账号枚举。
        $user = User::where('email', $request->input('email'))->first();

        if ($user) {
            $token = Password::createToken($user);
            $user->notify(new PasswordResetNotification($token));

            app(AuditLogger::class)->record('password.reset_requested', $user->getKey(), metadata: [
                'email' => $user->email,
            ]);
        }

        return back()->with('status', '如果该邮箱已注册，重置链接已发送，请查收邮件。');
    }
}

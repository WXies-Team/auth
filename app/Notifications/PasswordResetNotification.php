<?php

namespace App\Notifications;

use Illuminate\Auth\Notifications\ResetPassword as BaseResetPassword;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;

/**
 * 密码重置邮件。复用 Laravel 内置 ResetPassword 的令牌生成与路由约定，
 * 仅替换文案与链接（中文 + 网关主题）。
 */
class PasswordResetNotification extends BaseResetPassword
{
    use Queueable;

    public function toMail($notifiable): MailMessage
    {
        $url = url(route('password.reset', [
            'token' => $this->token,
            'email' => $notifiable->getEmailForPasswordReset(),
        ], false));

        return (new MailMessage)
            ->subject('重置密码')
            ->greeting('重置你的密码')
            ->line('收到此邮件是因为有人请求重置统一登录网关账号的密码。')
            ->line('如果不是你本人操作，忽略此邮件即可，密码不会改变。')
            ->action('重置密码', $url)
            ->line('此链接 '.config('auth.passwords.users.expire').' 分钟内有效。')
            ->line('如果按钮无法点击，请复制以下链接到浏览器打开：')
            ->line($url);
    }
}

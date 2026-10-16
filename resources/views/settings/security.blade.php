<x-layout title="安全设置">
    <x-top-nav active="security" />
    <div class="max-w-xl mx-auto py-10 px-4">
        <h1 class="text-[28px] font-semibold tracking-[-0.5px] mb-6">安全设置</h1>

        <section class="card p-5 flex items-center gap-4 mb-4">
            <div class="w-12 h-12 rounded-full flex items-center justify-center text-white text-[19px] font-semibold shrink-0"
                 style="background: var(--accent)">{{ mb_substr(auth()->user()->name, 0, 1) }}</div>
            <div class="min-w-0">
                <div class="text-[17px] font-semibold truncate">{{ auth()->user()->name }}</div>
                <div class="text-[15px] label-secondary truncate">{{ auth()->user()->email }}</div>
            </div>
        </section>

        @if ($recoveryCodes)
            <section class="rounded-2xl p-6 mb-6 border" style="background: color-mix(in srgb, var(--color-amber) 10%, var(--color-surface)); border-color: color-mix(in srgb, var(--color-amber) 30%, transparent)">
                <h2 class="font-semibold mb-1" style="color: var(--color-amber)">恢复码已生成</h2>
                <p class="text-[15px] mb-4" style="color: var(--color-label-secondary)">请立即保存到密码管理器——这是丢失验证器时唯一的找回方式，每个恢复码只能使用一次。</p>
                <div class="grid grid-cols-2 gap-2 font-mono text-[15px] card p-4">
                    @foreach ($recoveryCodes as $code)
                        <span>{{ $code }}</span>
                    @endforeach
                </div>
            </section>
        @endif

        <section class="card p-6 mb-4">
            <div class="flex items-start justify-between mb-5">
                <div>
                    <h2 class="font-semibold text-[17px]">两步验证（TOTP）</h2>
                    <p class="text-[15px] label-secondary mt-0.5">登录时还需输入验证器应用的动态验证码</p>
                </div>
                <span class="text-[13px] font-medium px-2.5 py-1 rounded-full"
                      style="{{ $enabled ? 'background: color-mix(in srgb, var(--color-green) 15%, transparent); color: var(--color-green)' : 'background: var(--color-surface-secondary); color: var(--color-label-secondary)' }}">
                    {{ $enabled ? '已启用' : '未启用' }}
                </span>
            </div>

            @if ($enabled)
                <div class="flex flex-col gap-2.5 items-start">
                    <form method="POST" action="{{ route('security.recovery-codes') }}">
                        @csrf
                        <button class="btn-secondary">重新生成恢复码</button>
                    </form>
                    <form method="POST" action="{{ route('security.two-factor.disable') }}"
                          onsubmit="return confirm('关闭两步验证会降低账户安全性，确定？')" class="space-y-2">
                        @csrf @method('DELETE')
                        <input type="password" name="password" required autocomplete="current-password"
                               placeholder="输入当前密码确认" class="input w-64">
                        <button class="btn" style="color: var(--color-red)">关闭两步验证</button>
                    </form>
                </div>
            @elseif ($pendingSecret)
                <div class="flex flex-col sm:flex-row gap-6 items-start">
                    <div class="card p-3 border separator">{!! $pendingSecret['qr'] !!}</div>
                    <div class="text-[15px] label-secondary space-y-2 min-w-0">
                        <p>1. 用 Google Authenticator / 1Password 等扫描二维码</p>
                        <p>2. 输入应用显示的 6 位验证码完成绑定</p>
                        <p class="break-all text-[13px] label-tertiary">密钥：{{ $pendingSecret['string'] }}</p>
                        <form method="POST" action="{{ route('security.two-factor.confirm') }}" class="flex gap-2 pt-1">
                            @csrf
                            <input name="code" required inputmode="numeric" maxlength="6" placeholder="000000"
                                   class="input w-32 text-center tracking-widest font-mono">
                            <button class="btn-primary">确认绑定</button>
                        </form>
                    </div>
                </div>
            @else
                <form method="POST" action="{{ route('security.two-factor.enable') }}">
                    @csrf
                    <button class="btn-primary">启用两步验证</button>
                </form>
            @endif
        </section>

        <section class="card p-6 mb-4">
            <h2 class="font-semibold text-[17px] mb-1">Passkey</h2>
            <p class="text-[15px] label-secondary mb-4">用指纹、面容或屏幕锁登录，无需密码</p>

            @if ($passkeys->isNotEmpty())
                <div class="divide-y separator mb-4">
                    @foreach ($passkeys as $passkey)
                        <div class="flex items-center justify-between py-3 gap-3">
                            <div class="text-[15px] min-w-0">
                                <span class="font-medium">{{ $passkey->name ?: 'Passkey' }}</span>
                                <div class="text-[13px] label-tertiary mt-0.5">添加于 {{ $passkey->created_at?->format('Y-m-d') }}</div>
                            </div>
                            <form method="POST" action="{{ route('passkey.destroy', $passkey) }}">
                                @csrf @method('DELETE')
                                <button class="text-[15px] hover:underline" style="color: var(--color-red)">删除</button>
                            </form>
                        </div>
                    @endforeach
                </div>
            @endif

            <div class="flex gap-2">
                <input data-passkey-name placeholder="设备名称（如：我的 MacBook）" class="input flex-1"
                       autocomplete="off">
                <button type="button" data-passkey-register class="btn-primary whitespace-nowrap">添加 Passkey</button>
            </div>
            <p data-passkey-error class="text-[15px] mt-2 hidden" style="color: var(--color-red)"></p>
        </section>

        <section class="card p-6">
            <h2 class="font-semibold text-[17px] mb-1">社交账号</h2>
            <p class="text-[15px] label-secondary mb-4">绑定后可用其一键登录</p>
            <div class="flex flex-wrap gap-2.5">
                @if (config('services.github.client_id'))
                    <a href="{{ route('social.redirect', ['provider' => 'github', 'intent' => 'link']) }}" class="btn-secondary">绑定 GitHub</a>
                @endif
                @if (config('services.google.client_id'))
                    <a href="{{ route('social.redirect', ['provider' => 'google', 'intent' => 'link']) }}" class="btn-secondary">绑定 Google</a>
                @endif
                <a href="{{ route('sessions.index') }}" class="btn-secondary">管理已登录设备</a>
            </div>
        </section>
    </div>
</x-layout>

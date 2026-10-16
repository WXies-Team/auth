<x-layout title="安全设置">
    <div class="max-w-xl mx-auto py-12 px-4">
        <a href="{{ route('home') }}" class="text-[15px] label-secondary hover:underline">← 返回</a>
        <h1 class="text-[28px] font-semibold tracking-tight mt-2 mb-1">安全设置</h1>
        <p class="text-[15px] label-secondary mb-8">管理两步验证与恢复方式</p>

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

        <section class="card p-6 mb-6">
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
                          onsubmit="return confirm('关闭两步验证会降低账户安全性，确定？')">
                        @csrf @method('DELETE')
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

        <section class="card p-6">
            <h2 class="font-semibold text-[17px] mb-1">Passkey</h2>
            <p class="text-[15px] label-secondary mb-4">在「已登录设备」页可管理；首次可在支持的浏览器中直接注册（即将上线管理界面）</p>
            <a href="{{ route('sessions.index') }}" class="btn-secondary inline-flex">管理已登录设备</a>
        </section>
    </div>
</x-layout>

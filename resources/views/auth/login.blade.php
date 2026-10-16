<x-layout title="登录">
    <div class="min-h-screen flex items-center justify-center px-4 py-10">
        <div class="w-full max-w-[380px]">
            {{-- 品牌区 --}}
            <div class="text-center mb-8">
                <div class="mx-auto mb-4 w-16 h-16 rounded-[14px] flex items-center justify-center text-3xl text-white shadow-lg"
                     style="background: linear-gradient(135deg, #007aff, #5e5ce6);">
                    ⬢
                </div>
                <h1 class="text-[22px] font-semibold tracking-tight">统一登录网关</h1>
                <p class="text-[15px] label-secondary mt-0.5">一次登录，通行所有项目</p>
            </div>

            <div class="card p-6">
                @if ($errors->any())
                    <div class="mb-4 rounded-xl bg-red-500/10 text-red-500 text-[15px] p-3">
                        {{ $errors->first() }}
                    </div>
                @endif

                <form method="POST" action="{{ isset($challenge) ? route('auth.reauthenticate') : route('login') }}" class="space-y-3">
                    @csrf
                    @if (isset($challenge))
                        <input type="hidden" name="transaction" value="{{ $challenge->transactionId }}">
                        <input type="hidden" name="challenge" value="{{ $challenge->token }}">
                    @endif

                    <div>
                        <input id="email" type="email" name="email" required autofocus
                               autocomplete="email webauthn" placeholder="邮箱"
                               class="input">
                    </div>

                    <div>
                        <input id="password" type="password" name="password" required
                               autocomplete="current-password" placeholder="密码"
                               class="input">
                    </div>

                    <button type="submit" class="btn-primary w-full">登录</button>
                </form>

                <div class="h-px my-4" style="background: var(--color-separator)"></div>

                <button type="button" data-passkey-login class="btn-secondary w-full">
                    <span class="text-lg">🔑</span> 使用 Passkey 登录
                </button>

                @if (config('services.github.client_id') || config('services.google.client_id'))
                    <div class="flex items-center gap-3 my-4">
                        <span class="h-px flex-1" style="background: var(--color-separator)"></span>
                        <span class="text-[13px] label-tertiary">或</span>
                        <span class="h-px flex-1" style="background: var(--color-separator)"></span>
                    </div>
                    <div class="space-y-2.5">
                        @if (config('services.github.client_id'))
                            <a href="{{ route('social.redirect', 'github') }}" class="btn-secondary w-full">使用 GitHub 登录</a>
                        @endif
                        @if (config('services.google.client_id'))
                            <a href="{{ route('social.redirect', 'google') }}" class="btn-secondary w-full">使用 Google 登录</a>
                        @endif
                    </div>
                @endif
            </div>

            <p class="text-center text-[13px] label-tertiary mt-6">
                受保护的统一身份服务 · 支持两步验证与 Passkey
            </p>
        </div>
    </div>
</x-layout>

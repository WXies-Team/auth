<x-layout title="登录">
    <div class="auth-scene flex items-center justify-center px-4 py-12">
        <div class="grain"></div>

        <div class="w-full max-w-[400px]">
            <div class="text-center mb-7 mat stagger-1">
                <div class="auth-mark mb-5">
                    <i data-lucide="lock" class="w-7 h-7 text-white" stroke-width="1.8"></i>
                </div>
                <h1 class="text-[34px] font-semibold tracking-[-0.9px] leading-tight mat stagger-2">统一登录网关</h1>
                <p class="auth-quiet text-[15px] mt-1.5 mat stagger-3">一次登录，通行所有项目</p>
            </div>

            <div class="auth-card p-7 mat stagger-4">
                @if (session('status'))
                    <div class="auth-note-ok note-in rounded-xl px-4 py-3 text-[15px] mb-4">
                        {{ session('status') }}
                    </div>
                @endif

                @if ($errors->any())
                    <div class="auth-note-error note-in rounded-xl px-4 py-3 text-[15px] mb-4">
                        {{ $errors->first() }}
                    </div>
                @endif

                {{-- 行业惯例（authentik / Logto / Casdoor）：邮箱与密码首屏同显 --}}
                <form method="POST"
                      action="{{ isset($challenge) ? route('auth.reauthenticate') : route('login') }}"
                      class="space-y-3">
                    @csrf
                    @if (isset($challenge))
                        <input type="hidden" name="transaction" value="{{ $challenge->transactionId }}">
                        <input type="hidden" name="challenge" value="{{ $challenge->token }}">
                    @endif

                    <input id="email" type="email" name="email" required
                           value="{{ old('email') }}" autocomplete="email webauthn"
                           placeholder="邮箱" aria-label="邮箱" class="auth-input">

                    <input id="password" type="password" name="password" required
                           autocomplete="current-password" placeholder="密码" aria-label="密码"
                           class="auth-input">

                    <label class="flex items-center gap-2.5 text-[15px] label-secondary cursor-pointer select-none">
                        <input type="checkbox" name="remember" value="1" class="rounded w-4 h-4 accent-[var(--accent)]">
                        记住我
                    </label>

                    <button type="submit" class="auth-primary mt-1">登录</button>
                </form>

                <div class="flex items-center gap-3 my-5">
                    <span class="h-px flex-1 auth-line"></span>
                    <span class="text-[13px] auth-faint">或</span>
                    <span class="h-px flex-1 auth-line"></span>
                </div>

                <button type="button" data-passkey-login class="auth-ghost">
                    <i data-lucide="key-round" class="w-[17px] h-[17px]"></i>
                    使用 Passkey 登录
                </button>

                @if (config('services.github.client_id') || config('services.google.client_id'))
                    <div class="space-y-2.5 mt-2.5">
                        @if (config('services.github.client_id'))
                            <a href="{{ route('social.redirect', 'github') }}" class="auth-ghost">
                                <svg width="17" height="17" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.6-1.4-1.4-1.8-1.4-1.8-1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 0-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.2.5-2.3 1.3-3.1-.2-.4-.6-1.6 0-3.2 0 0 1-.3 3.4 1.2a11.5 11.5 0 0 1 6 0c2.4-1.5 3.4-1.2 3.4-1.2.6 1.6.2 2.8.1 3.2.8.8 1.3 1.9 1.3 3.2 0 4.6-2.8 5.6-5.5 5.9.5.4.9 1 .9 2.2v3.3c0 .3.1.7.8.6A12 12 0 0 0 12 .3"/></svg>
                                使用 GitHub 登录
                            </a>
                        @endif
                        @if (config('services.google.client_id'))
                            <a href="{{ route('social.redirect', 'google') }}" class="auth-ghost">
                                <svg width="17" height="17" viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5a5.6 5.6 0 0 1-2.4 3.6v3h3.9c2.3-2.1 3.5-5.2 3.5-8.8"/><path fill="#34A853" d="M12 24c3.2 0 6-1.1 8-2.9l-3.9-3a7.4 7.4 0 0 1-11.1-3.9H1.3v3.1A12 12 0 0 0 12 24"/><path fill="#FBBC05" d="M5 14.3a7.2 7.2 0 0 1 0-4.6V6.6H1.3a12 12 0 0 0 0 10.8z"/><path fill="#EA4335" d="M12 4.8c1.8 0 3.4.6 4.6 1.8l3.4-3.4A12 12 0 0 0 1.3 6.6L5 9.7a7.2 7.2 0 0 1 7-4.9"/></svg>
                                使用 Google 登录
                            </a>
                        @endif
                    </div>
                @endif
            </div>

            <p class="text-center text-[13px] auth-faint mt-6 mat stagger-5">
                在邮箱框可直接使用浏览器保存的 Passkey 登录
            </p>
        </div>
    </div>
</x-layout>

<x-layout title="登录">
    <div class="auth-scene flex items-center justify-center px-4 py-12"
         x-data="loginFlow(@js(old('email', '')))" x-cloak>
        <div class="grain"></div>

        <div class="w-full max-w-[400px]">

            {{-- 品牌光徽 + 标题 --}}
            <div class="text-center mb-7">
                <div class="auth-mark mb-5">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2.5"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </div>
                <h1 class="text-[30px] font-semibold tracking-[-0.6px] leading-tight">统一登录网关</h1>
                <p class="auth-quiet text-[15px] mt-1.5">一次登录，通行所有项目</p>
            </div>

            <div class="auth-card rounded-[22px] p-7">
                @if (session('status'))
                    <div x-data x-transition.opacity.duration.200ms
                         class="auth-note-ok rounded-xl px-4 py-3 text-[15px] mb-4">
                        {{ session('status') }}
                    </div>
                @endif

                @if ($errors->any())
                    <div x-data x-show="stage !== 'password'" x-transition.opacity.duration.200ms
                         class="auth-note-error rounded-xl px-4 py-3 text-[15px] mb-4">
                        {{ $errors->first() }}
                    </div>
                @endif

                <form method="POST"
                      action="{{ isset($challenge) ? route('auth.reauthenticate') : route('login') }}"
                      @submit="(event) => { if (stage === 'identifier') { event.preventDefault(); continueWithEmail(); } else { loading = true; } }">
                    @csrf
                    @if (isset($challenge))
                        <input type="hidden" name="transaction" value="{{ $challenge->transactionId }}">
                        <input type="hidden" name="challenge" value="{{ $challenge->token }}">
                    @endif

                    {{-- 第一步：只问「你是谁」（Passkey autofill 锚定在此框） --}}
                    <template x-if="stage === 'identifier'">
                        <div x-transition:enter="transition ease-out duration-150" x-transition:enter-start="opacity-0 translate-x-2" x-transition:enter-end="opacity-100 translate-x-0">
                            <input id="email" type="email" name="email" required x-ref="email"
                                   x-model="email" autocomplete="email webauthn" placeholder="name@example.com"
                                   aria-label="邮箱"
                                   class="auth-input">
                            <button type="submit" class="auth-primary mt-3.5" :disabled="loading">
                                <span x-show="!loading">继续</span>
                                <span x-show="loading" class="inline-block w-4 h-4 rounded-full border-2 border-white/40 border-t-white animate-spin"></span>
                            </button>
                        </div>
                    </template>

                    {{-- 第二步：证明你是你 --}}
                    <template x-if="stage === 'password'">
                        <div class="space-y-3" x-transition:enter="transition ease-out duration-150" x-transition:enter-start="opacity-0 translate-x-2" x-transition:enter-end="opacity-100 translate-x-0">
                            <div class="flex items-center justify-between rounded-xl px-3.5 py-2.5"
                                 style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.07)">
                                <span class="text-[15px] truncate text-white/90" x-text="email"></span>
                                <button type="button" @click="stage = 'identifier'; focusEmail()"
                                        class="text-[15px] flex-shrink-0 ml-3 text-blue-400 hover:text-blue-300">
                                    修改
                                </button>
                            </div>
                            <div class="relative">
                                <input :type="showPassword ? 'text' : 'password'" name="password" required
                                       x-ref="password" autocomplete="current-password" placeholder="输入密码"
                                       aria-label="密码"
                                       class="auth-input pr-14">
                                <button type="button" @click="showPassword = !showPassword"
                                        class="absolute right-3.5 top-1/2 -translate-y-1/2 text-[13px] auth-faint hover:text-white/70"
                                        x-text="showPassword ? '隐藏' : '显示'"></button>
                            </div>
                            <label class="flex items-center gap-2.5 text-[15px] auth-quiet cursor-pointer select-none">
                                <input type="checkbox" name="remember" value="1"
                                       class="rounded accent-blue-500 w-4 h-4">
                                记住此设备
                            </label>
                            @if ($errors->any())
                                <p class="text-[15px]" style="color: #ff7b72">{{ $errors->first() }}</p>
                            @endif
                            <button type="submit" class="auth-primary" :disabled="loading">
                                <span x-show="!loading">登录</span>
                                <span x-show="loading" class="inline-block w-4 h-4 rounded-full border-2 border-white/40 border-t-white animate-spin"></span>
                            </button>
                        </div>
                    </template>
                </form>

                <div class="flex items-center gap-3 my-5">
                    <span class="h-px flex-1 auth-line"></span>
                    <span class="text-[13px] auth-faint">或</span>
                    <span class="h-px flex-1 auth-line"></span>
                </div>

                {{-- Passkey：显式入口（邮箱框 autofill 之外的兜底） --}}
                <button type="button" data-passkey-login class="auth-ghost" @click="loading = true">
                    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
                    使用 Passkey 登录
                </button>

                @if (config('services.github.client_id') || config('services.google.client_id'))
                    <div class="space-y-2.5 mt-2.5">
                        @if (config('services.github.client_id'))
                            <a href="{{ route('social.redirect', 'github') }}" class="auth-ghost">
                                <svg width="17" height="17" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2c-3.3.7-4-1.6-4-1.6-.6-1.4-1.4-1.8-1.4-1.8-1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 0-.8.4-1.3.7-1.6-2.7-.3-5.5-1.3-5.5-6 0-1.2.5-2.3 1.3-3.1-.2-.4-.6-1.6 0-3.2 0 0 1-.3 3.4 1.2a11.5 11.5 0 0 1 6 0c2.4-1.5 3.4-1.2 3.4-1.2.6 1.6.2 2.8.1 3.2.8.8 1.3 1.9 1.3 3.2 0 4.6-2.8 5.6-5.5 5.9.5.4.9 1 .9 2.2v3.3c0 .3.1.7.8.6A12 12 0 0 0 12 .3"/></svg>
                                使用 GitHub 继续
                            </a>
                        @endif
                        @if (config('services.google.client_id'))
                            <a href="{{ route('social.redirect', 'google') }}" class="auth-ghost">
                                <svg width="17" height="17" viewBox="0 0 24 24"><path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5a5.6 5.6 0 0 1-2.4 3.6v3h3.9c2.3-2.1 3.5-5.2 3.5-8.8"/><path fill="#34A853" d="M12 24c3.2 0 6-1.1 8-2.9l-3.9-3a7.4 7.4 0 0 1-11.1-3.9H1.3v3.1A12 12 0 0 0 12 24"/><path fill="#FBBC05" d="M5 14.3a7.2 7.2 0 0 1 0-4.6V6.6H1.3a12 12 0 0 0 0 10.8z"/><path fill="#EA4335" d="M12 4.8c1.8 0 3.4.6 4.6 1.8l3.4-3.4A12 12 0 0 0 1.3 6.6L5 9.7a7.2 7.2 0 0 1 7-4.9"/></svg>
                                使用 Google 继续
                            </a>
                        @endif
                    </div>
                @endif
            </div>

            <p class="text-center text-[13px] auth-faint mt-6">
                在邮箱框中可直接使用 Passkey 登录
            </p>
        </div>
    </div>

    @push('scripts')
    <script>
        function loginFlow(oldEmail) {
            return {
                stage: 'identifier',
                email: oldEmail || '',
                showPassword: false,
                loading: false,
                continueWithEmail() {
                    if (!this.email || !this.email.includes('@')) {
                        this.focusEmail();
                        return;
                    }
                    this.stage = 'password';
                    this.$nextTick(() => this.$refs.password?.focus());
                },
                focusEmail() {
                    this.$nextTick(() => this.$refs.email?.focus());
                },
                init() {
                    if (oldEmail) this.stage = 'password';
                },
            };
        }
    </script>
    @endpush
</x-layout>

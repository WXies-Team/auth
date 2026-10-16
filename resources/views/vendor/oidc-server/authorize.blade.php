<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="dark">
    <title>授权请求 · 统一登录网关</title>
    @vite(['resources/css/app.css'])
</head>
<body class="auth-scene flex items-center justify-center px-4 py-10" x-cloak>
    <div class="grain"></div>

    <div class="w-full max-w-[400px]">
        <div class="text-center mb-7">
            <div class="auth-mark mb-5">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2.5"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <h1 class="text-[30px] font-semibold tracking-[-0.6px] leading-tight">授权请求</h1>
            <p class="auth-quiet text-[15px] mt-1.5">你正在使用统一登录网关登录</p>
        </div>

        <div class="auth-card rounded-[22px] p-7">
            <div class="text-center mb-5">
                <p class="text-[17px] text-white">
                    <span class="font-semibold">{{ $client->name }}</span> 请求访问你的账户
                </p>
                <p class="auth-quiet text-[15px] mt-1">它将能够：</p>
            </div>

            @if (count($scopes) > 0)
                <ul class="space-y-2.5 mb-6">
                    @foreach ($scopes as $scope)
                        <li class="flex items-start gap-3 text-[15px] text-white/90">
                            <span class="mt-0.5 w-5 h-5 rounded-full flex-shrink-0 flex items-center justify-center"
                                  style="background: rgba(48,209,88,0.16)">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>
                            </span>
                            <span>{{ $scope->description }}</span>
                        </li>
                    @endforeach
                </ul>
            @endif

            <div class="space-y-2.5">
                <form method="post" action="{{ route('passport.authorizations.approve') }}">
                    @csrf
                    <input type="hidden" name="transaction" value="{{ $transactionId }}">
                    <input type="hidden" name="auth_token" value="{{ $authToken }}">
                    <button type="submit" class="auth-primary">允许</button>
                </form>
                <form method="post" action="{{ route('passport.authorizations.deny') }}">
                    @csrf
                    @method('DELETE')
                    <input type="hidden" name="transaction" value="{{ $transactionId }}">
                    <input type="hidden" name="auth_token" value="{{ $authToken }}">
                    <button type="submit" class="auth-ghost">拒绝</button>
                </form>
            </div>
        </div>

        <p class="text-center text-[13px] auth-faint mt-6">以 {{ auth()->user()?->email }} 的身份</p>
    </div>
</body>
</html>

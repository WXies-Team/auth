<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <title>授权请求 · 统一登录网关</title>
    @vite(['resources/css/app.css'])
</head>
<body class="min-h-screen flex items-center justify-center px-4">
    <div class="w-full max-w-[380px]">
        <div class="text-center mb-6">
            <div class="mx-auto mb-4 w-14 h-14 rounded-[14px] flex items-center justify-center text-2xl text-white shadow-lg"
                 style="background: linear-gradient(135deg, #007aff, #5e5ce6);">⬢</div>
            <h1 class="text-[22px] font-semibold tracking-tight">授权请求</h1>
        </div>

        <div class="card p-6">
            <p class="text-[17px] text-center mb-1">
                <span class="font-semibold">{{ $client->name }}</span> 请求访问你的账户
            </p>
            <p class="text-[15px] label-secondary text-center mb-4">它将能够：</p>

            @if (count($scopes) > 0)
                <ul class="text-[15px] space-y-1.5 mb-6">
                    @foreach ($scopes as $scope)
                        <li class="flex items-start gap-2">
                            <span style="color: var(--color-green)">✓</span>
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
                    <button type="submit" class="btn-primary w-full">允许</button>
                </form>
                <form method="post" action="{{ route('passport.authorizations.deny') }}">
                    @csrf
                    @method('DELETE')
                    <input type="hidden" name="transaction" value="{{ $transactionId }}">
                    <input type="hidden" name="auth_token" value="{{ $authToken }}">
                    <button type="submit" class="btn-secondary w-full">拒绝</button>
                </form>
            </div>
        </div>

        <p class="text-center text-[13px] label-tertiary mt-6">以 {{ auth()->user()?->email }} 的身份</p>
    </div>
</body>
</html>

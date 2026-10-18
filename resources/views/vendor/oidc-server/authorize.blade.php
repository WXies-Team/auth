<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <title>授权请求 · 统一登录网关</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="auth-scene flex items-center justify-center px-4 py-10">
    <div class="grain"></div>

    <div class="w-full max-w-[400px]">
        {{-- 应用标识 + 请求主体（GitHub「Grant <app> access」/ Google「wants to access」模式） --}}
        <div class="text-center mb-6">
            <div class="auth-mark mb-5 mx-auto">
                <i data-lucide="box" class="w-7 h-7 text-white" stroke-width="1.8"></i>
            </div>
            <h1 class="text-[26px] font-semibold tracking-[-0.6px] leading-tight">
                <span class="font-semibold">{{ $client->name }}</span> 请求访问你的账号
            </h1>
        </div>

        <div class="auth-card rounded-[22px] p-7">
            {{-- 当前登录身份（Google「Signed in as」） --}}
            <div class="flex items-center gap-3 pb-5 mb-5 border-b" style="border-color: var(--hairline)">
                <div class="w-9 h-9 rounded-full flex items-center justify-center text-white text-[15px] font-semibold shrink-0"
                     style="background: var(--accent)">{{ mb_substr($user->name ?? '', 0, 1) }}</div>
                <div class="min-w-0">
                    <div class="text-[13px] auth-quiet">当前登录账号</div>
                    <div class="text-[15px] truncate">{{ $user->email }}</div>
                </div>
            </div>

            <p class="text-[15px] auth-quiet mb-3">{{ $client->name }} 将获得以下权限：</p>

            @if (count($scopes) > 0)
                <ul class="space-y-2.5 mb-5">
                    @foreach ($scopes as $scope)
                        <li class="flex items-start gap-3 text-[15px] text-[var(--ink)]">
                            <span class="mt-0.5 w-5 h-5 rounded-full flex-shrink-0 flex items-center justify-center"
                                  style="background: rgba(48,209,88,0.16)">
                                <i data-lucide="check" class="w-3 h-3" style="color: var(--success-ink)"></i>
                            </span>
                            <span>{{ config("scopes.{$scope->id}", $scope->description) }}</span>
                        </li>
                    @endforeach
                </ul>
            @endif

            <div class="space-y-2.5">
                <form method="post" action="{{ route('passport.authorizations.approve') }}">
                    @csrf
                    <input type="hidden" name="transaction" value="{{ $transactionId }}">
                    <input type="hidden" name="auth_token" value="{{ $authToken }}">
                    <button type="submit" class="auth-primary">授权并继续</button>
                </form>
                <form method="post" action="{{ route('passport.authorizations.deny') }}">
                    @csrf
                    @method('DELETE')
                    <input type="hidden" name="transaction" value="{{ $transactionId }}">
                    <input type="hidden" name="auth_token" value="{{ $authToken }}">
                    <button type="submit" class="auth-ghost">取消</button>
                </form>
            </div>
        </div>

        <p class="text-center text-[13px] auth-quiet mt-6">
            授权即表示你同意 {{ $client->name }} 按上述范围访问你的账号
        </p>
    </div>
</body>
</html>

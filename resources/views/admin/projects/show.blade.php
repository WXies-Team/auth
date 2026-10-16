<x-layout title="{{ $project->name }}">
    <x-app-shell active="admin">
    <div class="py-12 px-4">
        <a href="{{ route('admin.dashboard') }}" class="text-[15px] label-secondary hover:underline">← 项目列表</a>

        <div class="flex items-center justify-between mt-2 mb-8">
            <div>
                <h1 class="text-[28px] font-semibold tracking-tight">{{ $project->name }}
                    <span class="text-[15px] label-tertiary font-mono">{{ $project->slug }}</span>
                </h1>
                <p class="text-[15px] label-secondary mt-0.5">{{ $project->description ?: '暂无描述' }}</p>
            </div>
            @can('update', $project)
                <a href="{{ route('admin.projects.edit', $project) }}" class="btn-secondary">编辑</a>
            @endcan
        </div>

        @if (session('status'))
            <div class="mb-4 rounded-xl p-3 text-[15px]"
                 style="background: color-mix(in srgb, var(--color-green) 12%, transparent); color: var(--color-green)">
                {{ session('status') }}
            </div>
        @endif
        @if (session('new_client'))
            <div class="mb-4 rounded-2xl p-4 text-[15px] border"
                 style="background: color-mix(in srgb, var(--color-amber) 10%, var(--color-surface)); border-color: color-mix(in srgb, var(--color-amber) 30%, transparent)">
                <p class="font-medium mb-1" style="color: var(--color-amber)">请立即保存——Client Secret 只显示这一次：</p>
                <p class="font-mono text-[13px] break-all" style="color: var(--color-label)">
                    ID: {{ session('new_client.id') }}<br>Secret: {{ session('new_client.secret') }}
                </p>
            </div>
        @endif

        {{-- 成员 --}}
        <section class="card p-6 mb-6">
            <h2 class="font-semibold text-[17px] mb-4">成员</h2>
            <div class="divide-y" style="border-color: var(--color-separator)">
                @foreach ($project->members as $member)
                    <div class="flex items-center justify-between py-3 gap-3">
                        <div class="text-[15px] min-w-0">
                            <span class="font-medium">{{ $member->name }}</span>
                            <span class="label-tertiary ml-2">{{ $member->email }}</span>
                        </div>
                        @can('manageMembers', $project)
                            <div class="flex items-center gap-2 flex-shrink-0">
                                <form method="POST" action="{{ route('admin.projects.members.update', [$project, $member]) }}" class="flex items-center gap-2">
                                    @csrf @method('PUT')
                                    <select name="role" class="input w-auto min-h-9 py-1 text-[15px]">
                                        <option value="member" @selected($member->pivot->role === 'member')>member</option>
                                        <option value="admin" @selected($member->pivot->role === 'admin')>admin</option>
                                    </select>
                                    <button class="text-[15px] hover:underline" style="color: var(--color-brand)">更新</button>
                                </form>
                                <form method="POST" action="{{ route('admin.projects.members.destroy', [$project, $member]) }}">
                                    @csrf @method('DELETE')
                                    <button class="text-[15px] hover:underline" style="color: var(--color-red)">移除</button>
                                </form>
                            </div>
                        @endcan
                    </div>
                @endforeach
            </div>
            @can('manageMembers', $project)
                <form method="POST" action="{{ route('admin.projects.members.store', $project) }}" class="flex gap-2 mt-4">
                    @csrf
                    <input name="email" type="email" required placeholder="按邮箱添加已有用户" class="input flex-1">
                    <select name="role" class="input w-auto py-1 min-h-11">
                        <option value="member">member</option>
                        <option value="admin">admin</option>
                    </select>
                    <button class="btn-primary whitespace-nowrap">添加</button>
                </form>
            @endcan
        </section>

        {{-- OAuth Client --}}
        <section class="card p-6 mb-6">
            <h2 class="font-semibold text-[17px] mb-1">OAuth Client</h2>
            <p class="text-[15px] label-secondary mb-4">下游项目作为 OIDC RP 接入时使用的凭证</p>
            <div class="divide-y" style="border-color: var(--color-separator)">
                @forelse ($project->clients as $client)
                    <div class="flex items-center justify-between py-3 gap-3">
                        <div class="text-[15px] min-w-0">
                            <span class="font-medium">{{ $client->name }}</span>
                            <div class="text-[13px] label-tertiary font-mono truncate">ID: {{ $client->getKey() }}</div>
                            <div class="text-[13px] label-tertiary truncate">Redirect: {{ implode(', ', (array) $client->redirect_uris) }}</div>
                        </div>
                        @can('manageClients', $project)
                            <div class="flex items-center gap-2 flex-shrink-0">
                                <form method="POST" action="{{ route('admin.projects.clients.rotate', [$project, $client]) }}">
                                    @csrf
                                    <button class="text-[15px] hover:underline" style="color: var(--color-brand)">轮换 Secret</button>
                                </form>
                                <form method="POST" action="{{ route('admin.projects.clients.destroy', [$project, $client]) }}">
                                    @csrf @method('DELETE')
                                    <button class="text-[15px] hover:underline" style="color: var(--color-red)">删除</button>
                                </form>
                            </div>
                        @endcan
                    </div>
                @empty
                    <div class="py-6 text-center label-tertiary text-[15px]">还没有 Client</div>
                @endforelse
            </div>
            @can('manageClients', $project)
                <form method="POST" action="{{ route('admin.projects.clients.store', $project) }}" class="space-y-2 mt-4">
                    @csrf
                    <input name="name" required placeholder="Client 名称（如：Web 前端）" class="input">
                    <div class="flex gap-2">
                        <input name="redirect" type="url" required placeholder="https://my-app.example.com/callback"
                               class="input flex-1 font-mono text-[15px]">
                        <button class="btn-primary whitespace-nowrap">创建 Client</button>
                    </div>
                </form>
            @endcan
        </section>

        @can('delete', $project)
            <form method="POST" action="{{ route('admin.projects.destroy', $project) }}" class="mt-8"
                  onsubmit="return confirm('删除项目会级联移除成员关系并吊销全部 Client 令牌，确定？')">
                @csrf @method('DELETE')
                <button class="text-[15px] hover:underline" style="color: var(--color-red)">删除此项目</button>
            </form>
        @endcan
    </div>
</x-app-shell>
</x-layout>

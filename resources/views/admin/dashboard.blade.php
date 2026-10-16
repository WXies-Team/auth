<x-layout title="管理后台">
    <x-app-shell active="admin">
    <div class="py-12 px-4">
        <div class="flex items-end justify-between gap-4 mb-6">
            <div>
                <h1 class="text-[28px] font-semibold tracking-tight leading-tight">管理后台</h1>
                <p class="text-[15px] label-secondary mt-0.5">
                    {{ auth()->user()->isSuperAdmin() ? '全局管理员' : '项目成员' }}
                </p>
            </div>
            <div class="flex items-center gap-2 flex-shrink-0 pb-0.5">
                @can('manage-users')
                    <a href="{{ route('admin.users.index') }}" class="btn-secondary text-[15px] font-normal">用户</a>
                    <a href="{{ route('admin.audit.index') }}" class="btn-secondary text-[15px] font-normal">审计</a>
                @endcan
                @can('create', App\Models\Project::class)
                    <a href="{{ route('admin.projects.create') }}" class="btn-primary">新建项目</a>
                @endcan
            </div>
        </div>

        @if (session('status'))
            <div class="mb-4 rounded-xl p-3 text-[15px]"
                 style="background: color-mix(in srgb, var(--color-green) 12%, transparent); color: var(--color-green)">
                {{ session('status') }}
            </div>
        @endif

        <div class="card divide-y" style="border-color: var(--color-separator)">
            @forelse ($projects as $project)
                <a href="{{ route('admin.projects.show', $project) }}" class="flex items-center justify-between p-5 transition hover:opacity-80">
                    <div>
                        <div class="font-medium text-[17px]">{{ $project->name }}
                            <span class="text-[13px] label-tertiary font-mono">{{ $project->slug }}</span>
                        </div>
                        <div class="text-[15px] label-secondary mt-0.5">{{ $project->description ?: '暂无描述' }}</div>
                    </div>
                    <div class="text-[15px] label-secondary whitespace-nowrap ml-4">{{ $project->members_count }} 成员 · {{ $project->clients_count }} Client</div>
                </a>
            @empty
                <div class="p-10 text-center label-tertiary text-[15px]">还没有项目</div>
            @endforelse
        </div>
    </div>
</x-app-shell>
</x-layout>

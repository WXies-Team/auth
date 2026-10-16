<x-layout title="用户管理">
    <x-app-shell active="admin">
    <div class="py-12 px-4">
        <h1 class="text-[28px] font-semibold tracking-tight mt-2 mb-8">用户管理</h1>

        @if (session('status'))
            <div class="mb-4 rounded-xl p-3 text-[15px]"
                 style="background: color-mix(in srgb, var(--color-green) 12%, transparent); color: var(--color-green)">
                {{ session('status') }}
            </div>
        @endif

        <div class="card divide-y" style="border-color: var(--color-separator)">
            @foreach ($users as $user)
                <div class="flex items-center justify-between p-4 gap-3">
                    <div class="text-[15px] min-w-0">
                        <span class="font-medium">{{ $user->name }}</span>
                        <span class="label-tertiary ml-2">{{ $user->email }}</span>
                        @if ($user->global_role)
                            <span class="ml-2 text-[13px] font-medium px-2 py-0.5 rounded-full"
                                  style="background: color-mix(in srgb, #af52de 18%, transparent); color: #bf5af2">全局管理员</span>
                        @endif
                        <div class="text-[13px] label-tertiary mt-0.5">{{ $user->projects_count }} 个项目</div>
                    </div>
                    <form method="POST" action="{{ route('admin.users.role', $user) }}" class="flex items-center gap-2 flex-shrink-0">
                        @csrf @method('PUT')
                        <label class="flex items-center gap-1.5 text-[15px]">
                            <input type="checkbox" name="global_role" value="super_admin" @checked($user->isSuperAdmin()) class="rounded accent-[var(--color-brand)]">
                            全局管理员
                        </label>
                        <button class="text-[15px] hover:underline" style="color: var(--color-brand)">保存</button>
                    </form>
                </div>
            @endforeach
        </div>

        <div class="mt-4">{{ $users->links() }}</div>
    </div>
</x-app-shell>
</x-layout>

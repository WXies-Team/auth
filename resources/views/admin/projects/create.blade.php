<x-layout title="新建项目">
    <x-top-nav active="admin" />
    <div class="max-w-lg mx-auto py-12 px-4">
        <a href="{{ route('admin.dashboard') }}" class="text-[15px] label-secondary hover:underline">← 项目列表</a>
        <h1 class="text-[28px] font-semibold tracking-tight mt-2 mb-6">新建项目</h1>

        @if ($errors->any())
            <div class="mb-4 rounded-xl bg-red-500/10 text-red-500 text-[15px] p-3">{{ $errors->first() }}</div>
        @endif

        <form method="POST" action="{{ route('admin.projects.store') }}" class="card p-6 space-y-4">
            @csrf
            <div>
                <label class="block text-[15px] font-medium mb-1.5">项目标识（slug）</label>
                <input name="slug" required pattern="[a-z0-9][a-z0-9-]*" placeholder="my-app" class="input font-mono">
            </div>
            <div>
                <label class="block text-[15px] font-medium mb-1.5">项目名称</label>
                <input name="name" required maxlength="128" placeholder="我的应用" class="input">
            </div>
            <div>
                <label class="block text-[15px] font-medium mb-1.5">描述（可选）</label>
                <textarea name="description" rows="3" maxlength="1000" class="input py-2.5"></textarea>
            </div>
            <div class="flex gap-3 pt-1">
                <button class="btn-primary">创建</button>
                <a href="{{ route('admin.dashboard') }}" class="btn-secondary">取消</a>
            </div>
        </form>
    </div>
</x-layout>

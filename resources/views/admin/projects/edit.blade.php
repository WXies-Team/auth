<x-layout title="编辑项目">
    <x-top-nav active="admin" />
    <div class="max-w-lg mx-auto py-12 px-4">
        <a href="{{ route('admin.projects.show', $project) }}" class="text-[15px] label-secondary hover:underline">← 返回项目</a>
        <h1 class="text-[28px] font-semibold tracking-tight mt-2 mb-6">编辑项目</h1>

        @if ($errors->any())
            <div class="mb-4 rounded-xl bg-red-500/10 text-red-500 text-[15px] p-3">{{ $errors->first() }}</div>
        @endif

        <form method="POST" action="{{ route('admin.projects.update', $project) }}" class="card p-6 space-y-4">
            @csrf @method('PUT')
            <div>
                <label class="block text-[15px] font-medium mb-1.5">项目名称</label>
                <input name="name" required maxlength="128" value="{{ old('name', $project->name) }}" class="input">
            </div>
            <div>
                <label class="block text-[15px] font-medium mb-1.5">描述</label>
                <textarea name="description" rows="3" maxlength="1000" class="input py-2.5">{{ old('description', $project->description) }}</textarea>
            </div>
            <button class="btn-primary">保存</button>
        </form>
    </div>
</x-layout>

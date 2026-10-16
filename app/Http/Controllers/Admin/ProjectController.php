<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

class ProjectController extends Controller
{
    public function create(): View
    {
        return view('admin.projects.create');
    }

    public function store(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'slug' => ['required', 'string', 'min:2', 'max:64', 'regex:/^[a-z0-9][a-z0-9-]*$/', Rule::unique('projects', 'slug')],
            'name' => ['required', 'string', 'max:128'],
            'description' => ['nullable', 'string', 'max:1000'],
        ]);

        $project = Project::create($data + ['created_by' => Auth::id()]);

        // 创建者默认成为该项目管理员
        $project->members()->attach(Auth::id(), ['role' => 'admin']);
        app(AuditLogger::class)->record('project.created', Auth::id(), 'project', $project->getKey());

        return redirect()->route('admin.projects.show', $project)->with('status', '项目已创建');
    }

    public function show(Project $project): View
    {
        Gate::authorize('view', $project);

        return view('admin.projects.show', [
            'project' => $project->load(['members', 'clients']),
        ]);
    }

    public function edit(Project $project): View
    {
        Gate::authorize('update', $project);

        return view('admin.projects.edit', ['project' => $project]);
    }

    public function update(Request $request, Project $project): RedirectResponse
    {
        Gate::authorize('update', $project);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:128'],
            'description' => ['nullable', 'string', 'max:1000'],
        ]);

        $project->update($data);
        app(AuditLogger::class)->record('project.updated', Auth::id(), 'project', $project->getKey());

        return redirect()->route('admin.projects.show', $project)->with('status', '项目已更新');
    }

    public function destroy(Project $project): RedirectResponse
    {
        Gate::authorize('delete', $project);
        app(AuditLogger::class)->record('project.deleted', Auth::id(), 'project', $project->getKey());
        $project->delete();

        return redirect()->route('admin.dashboard')->with('status', '项目已删除');
    }
}

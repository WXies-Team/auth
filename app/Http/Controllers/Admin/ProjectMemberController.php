<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Models\User;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

class ProjectMemberController extends Controller
{
    public function store(Request $request, Project $project): RedirectResponse
    {
        Gate::authorize('manageMembers', $project);

        $data = $request->validate([
            'email' => ['required', 'email', Rule::exists('users', 'email')],
            'role' => ['required', Rule::in(['admin', 'member'])],
        ]);

        $user = User::where('email', $data['email'])->firstOrFail();

        $project->members()->syncWithoutDetaching([
            $user->getKey() => ['role' => $data['role']],
        ]);
        app(AuditLogger::class)->record('member.added', Auth::id(), 'project', $project->getKey(), [
            'member_id' => $user->getKey(), 'role' => $data['role'],
        ]);

        return back()->with('status', '成员已添加');
    }

    public function update(Request $request, Project $project, User $user): RedirectResponse
    {
        Gate::authorize('manageMembers', $project);

        $data = $request->validate([
            'role' => ['required', Rule::in(['admin', 'member'])],
        ]);

        $project->members()->updateExistingPivot($user->getKey(), ['role' => $data['role']]);
        app(AuditLogger::class)->record('member.role_changed', Auth::id(), 'project', $project->getKey(), [
            'member_id' => $user->getKey(), 'role' => $data['role'],
        ]);

        return back()->with('status', '角色已更新');
    }

    public function destroy(Project $project, User $user): RedirectResponse
    {
        Gate::authorize('manageMembers', $project);
        $project->members()->detach($user->getKey());
        app(AuditLogger::class)->record('member.removed', Auth::id(), 'project', $project->getKey(), [
            'member_id' => $user->getKey(),
        ]);

        return back()->with('status', '成员已移除');
    }
}

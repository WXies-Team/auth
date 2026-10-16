<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

/**
 * 用户与全局角色管理（仅全局管理员）。
 */
class UserController extends Controller
{
    public function index(): View
    {
        return view('admin.users', [
            'users' => User::withCount('projects')->latest()->paginate(20),
        ]);
    }

    public function updateRole(Request $request, User $user): RedirectResponse
    {
        $data = $request->validate([
            'global_role' => ['nullable', Rule::in(['super_admin'])],
        ]);

        $user->forceFill(['global_role' => $data['global_role'] ?? null])->save();
        app(AuditLogger::class)->record('user.global_role_changed', auth()->id(), 'user', $user->getKey(), [
            'global_role' => $data['global_role'] ?? null,
        ]);

        return back()->with('status', '全局角色已更新');
    }
}

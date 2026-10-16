<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Project;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

class DashboardController extends Controller
{
    public function __invoke(): View
    {
        $user = Auth::user();

        $projects = $user->isSuperAdmin()
            ? Project::withCount(['members', 'clients'])->latest()->get()
            : $user->projects()->withCount(['members', 'clients'])->latest('projects.id')->get();

        return view('admin.dashboard', [
            'projects' => $projects,
            'canCreate' => $user->isSuperAdmin(),
        ]);
    }
}

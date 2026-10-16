<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use Illuminate\View\View;

class AuditController extends Controller
{
    public function index(): View
    {
        return view('admin.audit', [
            'logs' => AuditLog::with('user')->latest('id')->paginate(50),
        ]);
    }
}

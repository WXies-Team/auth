<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Laravel\Passport\Client;

class ProjectClientController extends Controller
{
    public function store(Request $request, Project $project): RedirectResponse
    {
        Gate::authorize('manageClients', $project);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:128'],
            'redirect' => ['required', 'url', 'max:500'],
        ]);

        $secret = Str::password(48, symbols: false);

        // 明文交给 Passport 的 secret mutator 自行 bcrypt（勿手动哈希，会双重哈希）。
        $client = DB::transaction(fn () => Client::create([
            'name' => $data['name'],
            'secret' => $secret,
            'redirect_uris' => [$data['redirect']],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'revoked' => false,
            'project_id' => $project->getKey(),
        ]));

        app(AuditLogger::class)->record('client.created', Auth::id(), 'oauth_client', null, [
            'client_id' => $client->getKey(), 'project_id' => $project->getKey(),
        ]);

        // secret 只在此刻明文返回一次（库里存哈希）
        return back()->with([
            'status' => 'Client 已创建',
            'new_client' => [
                'id' => $client->getKey(),
                'secret' => $secret,
            ],
        ]);
    }

    public function destroy(Project $project, Client $client): RedirectResponse
    {
        Gate::authorize('manageClients', $project);

        abort_unless($client->project_id === $project->getKey(), 404);

        // 级联吊销该 client 的所有 token
        app(AuditLogger::class)->record('client.deleted', Auth::id(), 'oauth_client', null, [
            'client_id' => $client->getKey(), 'project_id' => $project->getKey(),
        ]);
        $client->tokens()->update(['revoked' => true]);
        $client->delete();

        return back()->with('status', 'Client 已删除，其令牌全部吊销');
    }

    public function rotateSecret(Project $project, Client $client): RedirectResponse
    {
        Gate::authorize('manageClients', $project);

        abort_unless($client->project_id === $project->getKey(), 404);

        $secret = Str::password(48, symbols: false);
        $client->update(['secret' => $secret]);
        app(AuditLogger::class)->record('client.secret_rotated', Auth::id(), 'oauth_client', null, [
            'client_id' => $client->getKey(),
        ]);

        return back()->with([
            'status' => 'Client Secret 已轮换，旧 secret 即刻失效',
            'new_client' => [
                'id' => $client->getKey(),
                'secret' => $secret,
            ],
        ]);
    }
}

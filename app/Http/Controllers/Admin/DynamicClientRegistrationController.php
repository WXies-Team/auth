<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Project;
use App\Services\AuditLogger;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth 2.0 Dynamic Client Registration（RFC 7591 注册 / RFC 7592 管理）。
 *
 * 注册用 initial access token 保护（网关配置 DCR_INITIAL_TOKEN，为空则关闭）；
 * 注册响应里的一次性 registration_access_token 用于后续管理（库里只存哈希）。
 * 注册出的 Client 归属于 DCR_DEFAULT_PROJECT 指定的项目（或第一个项目）。
 */
class DynamicClientRegistrationController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        $initial = config('oidc.dcr_initial_token');

        if (! $initial || ! hash_equals($initial, (string) $request->bearerToken())) {
            return response()->json(['error' => 'invalid_token'], 401);
        }

        $data = $request->validate([
            'redirect_uris' => ['required', 'array', 'min:1'],
            'redirect_uris.*' => ['url', 'max:500'],
            'client_name' => ['required', 'string', 'max:128'],
            'token_endpoint_auth_method' => ['nullable', 'in:client_secret_basic,client_secret_post'],
            'grant_types' => ['nullable', 'array'],
            'backchannel_logout_uri' => ['nullable', 'url', 'max:500'],
        ]);

        $registrationToken = Str::password(64, symbols: false);
        $secret = Str::password(48, symbols: false);
        $projectId = config('oidc.dcr_default_project_id') ?: Project::orderBy('id')->value('id');

        $allowedGrants = ['authorization_code', 'refresh_token', 'client_credentials'];
        $grantTypes = array_values(array_intersect($data['grant_types'] ?? [], $allowedGrants));
        if ($grantTypes === []) {
            $grantTypes = ['authorization_code'];
        }
        // 纯机密客户端（仅 client_credentials）不需要 redirect_uri，但 RFC 7591 要求注册时提供；此处保留。

        // 明文交给 Passport 的 secret mutator 自行 bcrypt。
        // 此前手动 sha256 会被 mutator 再 bcrypt 一次，导致令牌端点校验永远失败。
        $client = Client::forceCreate([
            'name' => $data['client_name'],
            'secret' => $secret,
            'redirect_uris' => $data['redirect_uris'],
            'grant_types' => $grantTypes,
            'revoked' => false,
            'backchannel_logout_uri' => $data['backchannel_logout_uri'] ?? null,
            'registration_access_token_hash' => hash('sha256', $registrationToken),
            'project_id' => $projectId,
        ]);

        app(AuditLogger::class)->record('dcr.registered', null, 'oauth_client', null, [
            'client_id' => $client->getKey(),
            'client_name' => $data['client_name'],
        ]);

        return response()->json([
            'client_id' => $client->getKey(),
            'client_secret' => $secret,
            'client_id_issued_at' => $client->created_at->getTimestamp(),
            'client_secret_expires_at' => 0,
            'registration_access_token' => $registrationToken,
            'registration_client_uri' => route('dcr.show', $client->getKey()),
            'client_name' => $client->name,
            'redirect_uris' => $client->redirect_uris,
            'grant_types' => $client->grant_types,
            'token_endpoint_auth_method' => $request->input('token_endpoint_auth_method', 'client_secret_basic'),
            'backchannel_logout_uri' => $client->backchannel_logout_uri,
        ], 201);
    }

    public function show(Request $request, string $clientId): JsonResponse
    {
        $client = $this->authorizeManagement($request, $clientId);

        if ($client instanceof JsonResponse) {
            return $client;
        }

        return response()->json($this->metadata($client));
    }

    public function update(Request $request, string $clientId): JsonResponse
    {
        $client = $this->authorizeManagement($request, $clientId);

        if ($client instanceof JsonResponse) {
            return $client;
        }

        $data = $request->validate([
            'redirect_uris' => ['sometimes', 'array', 'min:1'],
            'redirect_uris.*' => ['url', 'max:500'],
            'client_name' => ['sometimes', 'string', 'max:128'],
            'backchannel_logout_uri' => ['nullable', 'url', 'max:500'],
        ]);

        if (array_key_exists('redirect_uris', $data)) {
            $client->redirect_uris = $data['redirect_uris'];
        }
        if (array_key_exists('client_name', $data)) {
            $client->name = $data['client_name'];
        }
        if (array_key_exists('backchannel_logout_uri', $data)) {
            $client->backchannel_logout_uri = $data['backchannel_logout_uri'];
        }
        $client->save();

        app(AuditLogger::class)->record('dcr.updated', null, 'oauth_client', null, [
            'client_id' => $client->getKey(),
        ]);

        return response()->json($this->metadata($client));
    }

    public function destroy(Request $request, string $clientId): Response
    {
        $client = $this->authorizeManagement($request, $clientId);

        if ($client instanceof JsonResponse) {
            return $client;
        }

        $client->tokens()->update(['revoked' => true]);
        $client->delete();

        app(AuditLogger::class)->record('dcr.deleted', null, 'oauth_client', null, [
            'client_id' => $clientId,
        ]);

        return response()->noContent();
    }

    private function authorizeManagement(Request $request, string $clientId): Client|JsonResponse
    {
        $client = Client::find($clientId);

        $token = $request->bearerToken();

        if (! $client || ! $token || ! $client->registration_access_token_hash
            || ! hash_equals($client->registration_access_token_hash, hash('sha256', $token))) {
            return response()->json(['error' => 'invalid_token'], 401);
        }

        return $client;
    }

    private function metadata(Client $client): array
    {
        return [
            'client_id' => $client->getKey(),
            'client_id_issued_at' => $client->created_at->getTimestamp(),
            'client_name' => $client->name,
            'redirect_uris' => $client->redirect_uris,
            'grant_types' => $client->grant_types,
            'backchannel_logout_uri' => $client->backchannel_logout_uri,
        ];
    }
}

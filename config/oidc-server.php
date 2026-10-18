<?php

declare(strict_types=1);
use Admin9\OidcServer\Services\DefaultClaims;
use App\Http\Middleware\EnforcePkce;
use App\OAuth\GatewayClient;

return [
    /*
    |--------------------------------------------------------------------------
    | OIDC Issuer
    |--------------------------------------------------------------------------
    */
    'issuer' => env('OIDC_ISSUER', env('APP_URL')),

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | The Eloquent model class used to look up users when generating ID tokens.
    | Falls back to the provider model of passport.guard if not set.
    | Must represent the same users as that session guard and the Passport
    | API guard protecting UserInfo. This option does not select a guard.
    |
    */
    'user_model' => null,

    /*
    |--------------------------------------------------------------------------
    | Passport Auto-Configuration
    |--------------------------------------------------------------------------
    |
    | When true, the package will automatically configure Passport scopes,
    | token TTLs, client model, and authorization view. The package server
    | always owns its protected grants and response independently of this flag.
    | Set to false if you want to configure Passport scopes/models/TTLs yourself.
    |
    */
    'configure_passport' => true,

    /*
    |--------------------------------------------------------------------------
    | Ignore Passport Routes
    |--------------------------------------------------------------------------
    |
    | When true, the package will call Passport::ignoreRoutes() to prevent
    | Passport from registering its own routes. Set to false if you need
    | Passport's default routes alongside the OIDC routes.
    |
    */
    'ignore_passport_routes' => true,

    /*
    |--------------------------------------------------------------------------
    | Authorization View
    |--------------------------------------------------------------------------
    |
    | The Blade view used for the OAuth authorization prompt.
    | Publish and customize, or point to your own view.
    |
    */
    'authorization_view' => 'oidc-server::authorize',

    // Shared atomic state must remain available for all nodes and token lifetimes.
    // Missing state fails closed. See the 2.0 host integration guide.
    'freshness' => [
        'redis_connection' => env('OIDC_FRESHNESS_REDIS_CONNECTION', 'default'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Client Model
    |--------------------------------------------------------------------------
    |
    | The Passport Client model class. The default always requires consent;
    | client ownership and existing tokens are not evidence of explicit consent.
    |
    */
    'client_model' => GatewayClient::class,

    /*
    |--------------------------------------------------------------------------
    | Supported Scopes
    |--------------------------------------------------------------------------
    */
    'scopes' => [
        'openid' => [
            'description' => 'OpenID Connect authentication',
            'claims' => ['sub'],
        ],
        'profile' => [
            'description' => 'Access user profile information',
            'claims' => ['name', 'nickname', 'picture', 'updated_at'],
        ],
        'email' => [
            'description' => 'Access user email address',
            'claims' => ['email', 'email_verified'],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Default Scopes
    |--------------------------------------------------------------------------
    */
    'default_scopes' => ['openid'],

    /*
    |--------------------------------------------------------------------------
    | Claims Resolver
    |--------------------------------------------------------------------------
    |
    | Map claim names to model attributes or callables.
    | Example: 'nickname' => 'public_name'
    | Example: 'picture' => fn($user) => $user->avatar_url
    |
    */
    'claims_resolver' => [],

    /*
    |--------------------------------------------------------------------------
    | Default Claims Map
    |--------------------------------------------------------------------------
    |
    | Map claim names to model attributes or callables for the default
    | resolution in HasOidcClaims. These are used when no claims_resolver
    | entry exists for a claim. Override to match your User model's schema.
    |
    | String values are treated as model attribute names (e.g., 'name' => 'name').
    | Callables receive the user model as the first argument:
    |   'email_verified' => fn($user) => $user->email_verified_at !== null
    |
    */
    'default_claims_map' => [
        'name' => 'name',
        'email' => 'email',
        'email_verified' => [DefaultClaims::class, 'emailVerified'],
        'updated_at' => [DefaultClaims::class, 'updatedAt'],
        // 数据边界：网关只对外输出基础资料（姓名/邮箱/头像），业务数据一律不进 claim。
        'picture' => 'avatar_url',
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Configuration
    |--------------------------------------------------------------------------
    */
    'tokens' => [
        'access_token_ttl' => (int) env('OIDC_ACCESS_TOKEN_TTL', 900),
        'refresh_token_ttl' => (int) env('OIDC_REFRESH_TOKEN_TTL', 604800),
        'id_token_ttl' => (int) env('OIDC_ID_TOKEN_TTL', 900),
    ],

    /*
    |--------------------------------------------------------------------------
    | Supported Response Types
    |--------------------------------------------------------------------------
    */
    'response_types_supported' => [
        'code',
    ],

    /*
    |--------------------------------------------------------------------------
    | Supported Grant Types
    |--------------------------------------------------------------------------
    */
    'grant_types_supported' => [
        'authorization_code',
        'refresh_token',
        // 与 discovery 宣告一致（OidcController 硬编码含 client_credentials）。
        // 启用后，client 的 grant_types 含此项即可走 M2M 令牌流。
        'client_credentials',
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Endpoint Auth Methods
    |--------------------------------------------------------------------------
    */
    'token_endpoint_auth_methods_supported' => [
        'client_secret_basic',
        'client_secret_post',
    ],

    /*
    |--------------------------------------------------------------------------
    | ID Token Signing Algorithms
    |--------------------------------------------------------------------------
    */
    'id_token_signing_alg_values_supported' => [
        'RS256',
    ],

    /*
    |--------------------------------------------------------------------------
    | Subject Types
    |--------------------------------------------------------------------------
    */
    'subject_types_supported' => [
        'public',
    ],

    /*
    |--------------------------------------------------------------------------
    | PKCE Code Challenge Methods
    |--------------------------------------------------------------------------
    */
    'code_challenge_methods_supported' => [
        'S256',
    ],

    /*
    |--------------------------------------------------------------------------
    | Post Logout Redirect URIs
    |--------------------------------------------------------------------------
    */
    'post_logout_redirect_uris_supported' => [],

    // Optional per-client logout URIs. Otherwise the client's OAuth redirect URIs
    // are reused with exact matching. The global list above is only for local,
    // confirmed logout without a client.
    'post_logout_redirect_uris' => [],

    // Explicitly authorize a confidential resource server to inspect tokens issued
    // to additional clients: caller client ID => [token-owning client ID, ...].
    // This never grants permission to revoke another client's tokens.
    'introspection_allowed_clients' => [],

    /*
    |--------------------------------------------------------------------------
    | Routes Configuration
    |--------------------------------------------------------------------------
    |
    | Control route registration and per-group middleware.
    | - discovery_middleware: Applied to /.well-known/* endpoints
    | - authorization_middleware: Additional policy middleware for authorization;
    |   the package owns guest/reauthentication behavior and filters native auth
    |   middleware. Complete authentication through the recorder/handler contract.
    | - token_middleware: Applied to /oauth/token, introspect, revoke
    | - userinfo_middleware: Applied to /oauth/userinfo (default: auth:api,
    |   which requires a valid Passport access token)
    |
    */
    'routes' => [
        'enabled' => true,
        'discovery_middleware' => [],
        // OAuth 2.1：所有客户端强制 PKCE（S256）。包内仅在提供了 challenge 时才强制 S256，
        // 此中间件前置拦截缺失 PKCE 的授权请求。
        'authorization_middleware' => [EnforcePkce::class],
        // RFC 6749 §4.4.1：令牌/内省/吊销端点须防爆破，按 IP+端点限流。
        'token_middleware' => ['throttle:60,1'],
        'userinfo_middleware' => ['auth:api'],
    ],
];

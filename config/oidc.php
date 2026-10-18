<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Dynamic Client Registration（RFC 7591）
    |--------------------------------------------------------------------------
    |
    | DCR_INITIAL_TOKEN 为空即关闭动态注册。设置后用它作为注册端点的
    | initial access token（配置明文，请求侧 Bearer 逐字节比对）。
    |
    */
    'dcr_initial_token' => env('DCR_INITIAL_TOKEN'),

    // 动态注册出的 Client 归属的项目 ID；为空则取最早创建的项目。
    'dcr_default_project_id' => env('DCR_DEFAULT_PROJECT_ID'),

    /*
    |--------------------------------------------------------------------------
    | 自助注册
    |--------------------------------------------------------------------------
    |
    | REGISTRATION_ENABLED 为真时开放 /register 自助注册。统一登录网关
    | 默认关闭（用户由管理员创建或社交登录 JIT 建号），需要开放时置真。
    |
    */
    'registration_enabled' => (bool) env('REGISTRATION_ENABLED', false),
];

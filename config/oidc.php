<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Dynamic Client Registration（RFC 7591）
    |--------------------------------------------------------------------------
    |
    | DCR_INITIAL_TOKEN 为空即关闭动态注册。设置后用它作为注册端点的
    | initial access token（hash 存储校验，见 controller）。
    |
    */
    'dcr_initial_token' => env('DCR_INITIAL_TOKEN'),

    // 动态注册出的 Client 归属的项目 ID；为空则取最早创建的项目。
    'dcr_default_project_id' => env('DCR_DEFAULT_PROJECT_ID'),
];

<?php

return [
    // 框架通用校验消息（中文）。未覆盖的键回退到 en。
    'required' => ':attribute不能为空。',
    'email' => ':attribute格式不正确。',
    'unique' => ':attribute已被使用。',
    'min' => [
        'string' => ':attribute至少需要:min个字符。',
        'array' => ':attribute至少需要:min项。',
        'file' => ':attribute不能小于:min KB。',
        'numeric' => ':attribute不能小于:min。',
    ],
    'max' => [
        'string' => ':attribute不能超过:max个字符。',
        'array' => ':attribute最多:max项。',
        'file' => ':attribute不能大于:max KB。',
        'numeric' => ':attribute不能大于:max。',
    ],
    'confirmed' => ':attribute两次输入不一致。',
    'url' => ':attribute必须是有效的链接。',
    'array' => ':attribute必须是数组。',
    'string' => ':attribute必须是文本。',
    'boolean' => ':attribute必须是 true 或 false。',
    'integer' => ':attribute必须是整数。',
    'date' => ':attribute不是有效日期。',
    'after' => ':attribute必须晚于:date。',
    'before' => ':attribute必须早于:date。',
    'in' => '所选的:attribute无效。',
    'not_in' => '所选的:attribute无效。',
    'nullable' => ':attribute可以为空。',
    'attribute' => [
        'email' => '邮箱',
        'password' => '密码',
        'password_confirmation' => '确认密码',
        'current_password' => '当前密码',
        'name' => '昵称',
        'code' => '验证码',
        'token' => '令牌',
    ],
];

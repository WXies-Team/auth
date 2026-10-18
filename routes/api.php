<?php

use App\Http\Controllers\Admin\DynamicClientRegistrationController;
use Illuminate\Support\Facades\Route;

// OAuth 2.0 Dynamic Client Registration（RFC 7591 / RFC 7592），Bearer 令牌认证。
// 管理端点同样限流：registration_access_token 虽为 64 位随机，仍防爆破枚举。
Route::post('/register', [DynamicClientRegistrationController::class, 'register'])
    ->middleware('throttle:10,1')
    ->name('dcr.register');
Route::get('/register/{clientId}', [DynamicClientRegistrationController::class, 'show'])
    ->middleware('throttle:30,1')
    ->name('dcr.show');
Route::put('/register/{clientId}', [DynamicClientRegistrationController::class, 'update'])
    ->middleware('throttle:30,1')
    ->name('dcr.update');
Route::delete('/register/{clientId}', [DynamicClientRegistrationController::class, 'destroy'])
    ->middleware('throttle:10,1')
    ->name('dcr.destroy');

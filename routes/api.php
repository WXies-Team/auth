<?php

use App\Http\Controllers\Admin\DynamicClientRegistrationController;
use Illuminate\Support\Facades\Route;

// OAuth 2.0 Dynamic Client Registration（RFC 7591 / RFC 7592），Bearer 令牌认证。
Route::post('/register', [DynamicClientRegistrationController::class, 'register'])
    ->middleware('throttle:10,1')
    ->name('dcr.register');
Route::get('/register/{clientId}', [DynamicClientRegistrationController::class, 'show'])->name('dcr.show');
Route::put('/register/{clientId}', [DynamicClientRegistrationController::class, 'update'])->name('dcr.update');
Route::delete('/register/{clientId}', [DynamicClientRegistrationController::class, 'destroy'])->name('dcr.destroy');

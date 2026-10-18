<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * 记住授权（skip consent）：用户对某 client 显式同意过的 scope 集合。
 *
 * 授权屏同意后记录；后续同 client 再次授权且请求 scope 为已同意集合的子集时
 * 静默跳过同意屏（GitHub 模式）。scope 扩大或 prompt=consent 时仍强制弹窗。
 * 用户在「已授权应用」撤销后删除对应记录，下次重新弹同意屏。
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_consents', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignUuid('client_id')->constrained('oauth_clients')->cascadeOnDelete();
            $table->json('scopes');
            $table->timestamps();

            $table->unique(['user_id', 'client_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_consents');
    }
};

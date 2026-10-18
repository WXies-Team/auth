<?php

namespace Database\Factories;

use App\Models\User;
use App\Models\UserConsent;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<UserConsent>
 */
class UserConsentFactory extends Factory
{
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'client_id' => $this->faker->uuid(),
            'scopes' => ['openid'],
        ];
    }
}

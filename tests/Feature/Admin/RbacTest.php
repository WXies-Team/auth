<?php

namespace Tests\Feature\Admin;

use App\Models\Project;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class RbacTest extends TestCase
{
    use RefreshDatabase;

    public function test_guest_is_redirected_from_admin(): void
    {
        $this->get('/admin')->assertRedirect('/login');
    }

    public function test_user_without_projects_cannot_access_admin(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->get('/admin')->assertForbidden();
    }

    public function test_project_member_can_access_admin_but_not_create_projects(): void
    {
        $user = User::factory()->create();
        $project = Project::factory()->create();
        $project->members()->attach($user->id, ['role' => 'member']);

        $this->actingAs($user)->get('/admin')->assertOk();
        $this->actingAs($user)->post('/admin/projects', ['slug' => 'x-app', 'name' => 'X'])
            ->assertForbidden();
    }

    public function test_super_admin_can_create_project_and_becomes_project_admin(): void
    {
        $admin = User::factory()->create();
        $admin->forceFill(['global_role' => 'super_admin'])->save();

        $this->actingAs($admin)->post('/admin/projects', ['slug' => 'new-app', 'name' => 'New App'])
            ->assertRedirect(route('admin.projects.show', Project::where('slug', 'new-app')->firstOrFail()));

        $project = Project::where('slug', 'new-app')->firstOrFail();
        $this->assertSame('admin', $project->roleOf($admin));
    }

    public function test_project_admin_cannot_grant_super_admin(): void
    {
        $owner = User::factory()->create();
        $project = Project::factory()->create();
        $project->members()->attach($owner->id, ['role' => 'admin']);

        $target = User::factory()->create();

        $this->actingAs($owner)
            ->put("/admin/users/{$target->id}/role", ['global_role' => 'super_admin'])
            ->assertForbidden();
    }

    public function test_only_project_admin_manages_members(): void
    {
        $member = User::factory()->create();
        $project = Project::factory()->create();
        $project->members()->attach($member->id, ['role' => 'member']);
        $target = User::factory()->create();

        $this->actingAs($member)
            ->post("/admin/projects/{$project->id}/members", ['email' => $target->email, 'role' => 'admin'])
            ->assertForbidden();
    }
}

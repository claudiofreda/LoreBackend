// Copyright Lukas Jech 2026. All Rights Reserved.

namespace LoreBackend.Database
{
    public record Org(long Id, string Slug, string Name);

    public record User(long Id, string Username, string PasswordHash, long? OrgId, bool IsAdmin, string? OrgSlug);

    public record Repo(long Id, string LoreId, long? OrgId, string? Slug, string Name, string? OrgSlug);

    public record Perm(long UserId, string RepoLoreId, string Perms);

    public record ApiKey(long Id, long UserId, string Name, string Created, string Username);

    public record ResourceGrant(string ResourceId, string[] Permission);
}
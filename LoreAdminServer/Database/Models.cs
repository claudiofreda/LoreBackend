// Copyright Lukas Jech 2026. All Rights Reserved.

namespace LoreBackend.Database
{
    public record Org(long Id, string Slug, string Name);

    public record User(long Id, string Username, string PasswordHash, bool IsAdmin)
    {
        // Organizations the user belongs to (local users can be in several). Loaded from user_orgs.
        public System.Collections.Generic.List<Org> Orgs { get; set; } = new System.Collections.Generic.List<Org>();
    }

    public record Repo(long Id, string LoreId, long? OrgId, string? Slug, string Name, string? OrgSlug);

    public record Perm(long UserId, string RepoLoreId, string Perms);

    public record ApiKey(long Id, long UserId, string Name, string Created, string Username);

    public record ResourceGrant(string ResourceId, string[] Permission);

    public record OidcIdentity(string Username, string? DisplayName, string? PreferredUsername, System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<string, string>> Claims);
}
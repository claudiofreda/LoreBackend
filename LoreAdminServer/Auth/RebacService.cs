// Copyright Lukas Jech 2026. All Rights Reserved.

using System.Linq;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Lore.Proto.Rebac;
using LoreBackend.Database;

namespace LoreBackend.Auth
{
    /// <summary>
    /// Service responsible for authorizing repository create/delete operations.
    /// The lore server calls this API during create and delete to check whether the caller has the necessary permissions.
    /// </summary>
    public class RebacService : RebacApi.RebacApiBase
    {
        readonly LoreStore _store;
        readonly TokenService _tokens;
        readonly ILogger<RebacService> _logger;

        public RebacService(LoreStore store, TokenService tokens, ILogger<RebacService> logger)
        {
            _store = store;
            _tokens = tokens;
            _logger = logger;
        }

        public override async Task<CreateResourceResponse> CreateResource(CreateResourceRequest request, ServerCallContext context)
        {
            User? user = await _tokens.AuthenticateAsync(context.RequestHeaders.GetValue("authorization"));
            string loreId = StripPrefix(request.ResourceId);
            string name = string.IsNullOrEmpty(request.ResourceName) ? loreId : request.ResourceName;
            _logger.LogInformation("CreateResource user={User} resource=urc-{LoreId} name={Name}", user?.Username ?? "?", loreId, name);
            if (user == null)
            {
                throw new RpcException(new Status(StatusCode.Unauthenticated, "not authenticated"));
            }

            int slash = name.IndexOf('/');
            string? orgSlug = slash >= 0 ? name.Substring(0, slash) : null;
            string repoSlug = slash >= 0 ? name.Substring(slash + 1) : name;

            if (_store.IsAdmin(user))
            {
                Org? adminOrg = orgSlug != null ? _store.GetOrgBySlug(orgSlug) : null;
                _store.UpsertRepo(loreId, adminOrg?.Id, repoSlug, name);
                return new CreateResourceResponse();
            }

            // Non-admin: may create under an org they belong to. Membership comes from DB orgs (local users) or the ACL (OIDC users) via IsInOrg.
            // The repo name must be prefixed with the org (org/repo). The creator becomes owner on local repos.
            if (orgSlug == null)
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "repository name must be prefixed with an organization (org/repo)"));
            }

            if (!_store.IsInOrg(user, orgSlug))
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, $"not authorized to create repositories under organization '{orgSlug}'"));
            }

            Org? org = _store.GetOrgBySlug(orgSlug);
            _store.UpsertRepo(loreId, org?.Id, repoSlug, name);
            _store.SetPerm(user.Id, loreId, new[] { "admin" });
            return new CreateResourceResponse();
        }

        public override async Task<DeleteResourceResponse> DeleteResource(DeleteResourceRequest request, ServerCallContext context)
        {
            User? user = await _tokens.AuthenticateAsync(context.RequestHeaders.GetValue("authorization"));
            string loreId = StripPrefix(request.ResourceId);
            _logger.LogInformation("DeleteResource user={User} resource=urc-{LoreId}", user?.Username ?? "?", loreId);
            if (user == null)
            {
                throw new RpcException(new Status(StatusCode.Unauthenticated, "not authenticated"));
            }

            // Delete authorization: admins always; everyone else must own the repo and currently be in the repo's org.
            // Losing org access removes delete rights, regaining it restores them.
            bool authorized;
            if (_store.IsAdmin(user))
            {
                authorized = true;
            }
            else
            {
                bool owns = _store.GetPerms(user.Id).Any(p => p.RepoLoreId == loreId);
                string? org = _store.RepoOrg(loreId);
                authorized = owns && org != null && _store.IsInOrg(user, org);
            }

            if (!authorized)
            {
                throw new RpcException(new Status(StatusCode.PermissionDenied, "not authorized to delete this repository"));
            }

            _store.DeleteRepo(loreId);
            return new DeleteResourceResponse();
        }

        static string StripPrefix(string resourceId)
        {
            return resourceId.StartsWith("urc-") ? resourceId.Substring(4) : resourceId;
        }
    }
}
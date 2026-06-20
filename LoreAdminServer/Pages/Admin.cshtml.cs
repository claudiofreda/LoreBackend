// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using LoreBackend.Database;
using LoreBackend.Server;

namespace LoreBackend.Pages
{
	[IgnoreAntiforgeryToken]
	public class AdminModel : PageModel
	{
		readonly LoreStore _store;
		readonly LoreOptions _options;

		public AdminModel(LoreStore store, IOptions<LoreOptions> options)
		{
			_store = store;
			_options = options.Value;
		}

		// In OIDC mode, identities and permissions come from the IdP + ACL rules, so the
		// dashboard is read-only: no local users to create and no manual grants to edit.
		public bool OidcEnabled => !string.IsNullOrEmpty(_options.Oidc.ClientId);
		public AclConfig Acl => _options.Acl;

		public List<Org> Orgs { get; private set; } = new List<Org>();
		public List<User> Users { get; private set; } = new List<User>();
		public List<Repo> Repos { get; private set; } = new List<Repo>();
		public Dictionary<long, List<Perm>> Perms { get; private set; } = new Dictionary<long, List<Perm>>();
		public List<OidcUserView> OidcUsers { get; private set; } = new List<OidcUserView>();

		public IReadOnlyList<string> AllPerms => LoreStore.AllPerms;
		public IEnumerable<User> Members => Users.Where(u => !u.IsAdmin);
		public string RepoName(string loreId) => Repos.FirstOrDefault(r => r.LoreId == loreId)?.Name ?? loreId;

		// Human label for a grant's resource: the wildcard, or the repo name behind urc-<id>.
		public string ResourceLabel(string resourceId)
		{
			if (resourceId == "urc-*")
			{
				return "all repositories";
			}

			string loreId = resourceId.StartsWith("urc-", StringComparison.Ordinal) ? resourceId.Substring(4) : resourceId;
			return RepoName(loreId);
		}

		// Claim types referenced by ACL entries - the ones worth showing per identity.
		public HashSet<string> RelevantClaimTypes => Acl.Entries
			.Select(e => e.Claim.Type)
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		public record OidcUserView(OidcIdentity Identity, List<ResourceGrant> Grants);

		public IActionResult OnGet()
		{
			IActionResult? denied = AuthorizeView();
			if (denied != null)
			{
				return denied;
			}
			Load();
			return Page();
		}

		public IActionResult OnPostOrg(string slug, string? name)
		{
			IActionResult? guard = RequireEditable();
			if (guard != null)
			{
				return guard;
			}
			_store.CreateOrg(slug, name);
			return RedirectToPage();
		}

		public IActionResult OnPostUser(string username, string password, long[]? orgIds, string? isAdmin)
		{
			IActionResult? guard = RequireEditable();
			if (guard != null)
			{
				return guard;
			}
			_store.CreateUser(username, password, orgIds ?? Array.Empty<long>(), isAdmin == "1");
			return RedirectToPage();
		}

		public IActionResult OnPostUserOrgs(long userId, long[]? orgIds)
		{
			IActionResult? guard = RequireEditable();
			if (guard != null)
			{
				return guard;
			}
			_store.SetUserOrgs(userId, orgIds ?? Array.Empty<long>());
			return RedirectToPage();
		}

		public IActionResult OnPostDeleteUser(long id)
		{
			IActionResult? guard = RequireEditable();
			if (guard != null)
			{
				return guard;
			}
			_store.DeleteUser(id);
			return RedirectToPage();
		}

		public IActionResult OnPostPerm(long userId, string repo, string[]? perm)
		{
			IActionResult? guard = RequireEditable();
			if (guard != null)
			{
				return guard;
			}
			_store.SetPerm(userId, repo, perm ?? Array.Empty<string>());
			return RedirectToPage();
		}

		void Load()
		{
			Orgs = _store.ListOrgs();
			Users = _store.ListUsers();
			Repos = _store.ListRepos();
			Perms = Users.ToDictionary(u => u.Id, u => _store.GetPerms(u.Id));

			if (OidcEnabled)
			{
				OidcUsers = _store.ListIdentities()
					.Select(identity =>
					{
						User? user = _store.GetUser(identity.Username);
						List<ResourceGrant> grants = user != null ? _store.ResourcesForUser(user) : new List<ResourceGrant>();
						return new OidcUserView(identity, grants);
					})
					.ToList();
			}
		}

		// Authorize viewing the dashboard. OIDC mode: require a signed-in OIDC user holding the
		// configured admin claim (challenge if not signed in). Local mode: Basic auth.
		IActionResult? AuthorizeView()
		{
			if (!OidcEnabled)
			{
				return RequireAdmin();
			}

			if (!(User.Identity?.IsAuthenticated ?? false))
			{
				return Challenge(new AuthenticationProperties { RedirectUri = "/admin" }, OpenIdConnectDefaults.AuthenticationScheme);
			}

			return IsOidcAdmin()
				? null
				: new ContentResult { StatusCode = 403, Content = "Forbidden: dashboard access requires the admin role." };
		}

		// True if the signed-in OIDC user holds the configured admin claim (type case-insensitive,
		// value exact - same as the ACL). Unconfigured claim type fails closed.
		bool IsOidcAdmin()
		{
			AclClaim admin = _options.Oidc.AdminClaim;
			if (string.IsNullOrEmpty(admin.Type))
			{
				return false;
			}

			return User.Claims.Any(c =>
				string.Equals(c.Type, admin.Type, StringComparison.OrdinalIgnoreCase) &&
				string.Equals(c.Value, admin.Value, StringComparison.Ordinal));
		}

		// Mutating handlers: read-only (403) in OIDC mode; Basic-auth admin in local mode.
		IActionResult? RequireEditable()
		{
			return OidcEnabled
				? new ContentResult { StatusCode = 403, Content = "Read-only: OIDC user permissions are managed by the ACL rules." }
				: RequireAdmin();
		}

		IActionResult? RequireAdmin()
		{
			string? authorization = Request.Headers.Authorization;
			if (authorization != null && authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
			{
				string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(authorization.Substring(6)));
				int separator = decoded.IndexOf(':');
				if (separator >= 0)
				{
					User? user = _store.GetUser(decoded.Substring(0, separator));
					if (user != null && user.IsAdmin && LoreStore.VerifyPassword(decoded.Substring(separator + 1), user.PasswordHash))
					{
						return null;
					}
				}
			}
			Response.Headers.WWWAuthenticate = "Basic realm=\"Lore Admin\"";
			return new ContentResult { StatusCode = 401, Content = "Auth required" };
		}
	}
}

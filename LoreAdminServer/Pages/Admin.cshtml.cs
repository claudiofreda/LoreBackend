// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using LoreBackend.Database;

namespace LoreBackend.Pages
{
	[IgnoreAntiforgeryToken]
	public class AdminModel : PageModel
	{
		readonly LoreStore _store;

		public AdminModel(LoreStore store)
		{
			_store = store;
		}

		public List<Org> Orgs { get; private set; } = new List<Org>();
		public List<User> Users { get; private set; } = new List<User>();
		public List<Repo> Repos { get; private set; } = new List<Repo>();
		public Dictionary<long, List<Perm>> Perms { get; private set; } = new Dictionary<long, List<Perm>>();
		public List<ApiKey> ApiKeys { get; private set; } = new List<ApiKey>();

		// Carries a freshly generated API token to the redirected page so it can be shown once.
		[TempData]
		public string? NewApiKey { get; set; }

		public IReadOnlyList<string> AllPerms => LoreStore.AllPerms;
		public IEnumerable<User> Members => Users.Where(u => !u.IsAdmin);
		public string RepoName(string loreId) => Repos.FirstOrDefault(r => r.LoreId == loreId)?.Name ?? loreId;

		public IActionResult OnGet()
		{
			IActionResult? denied = RequireAdmin();
			if (denied != null)
			{
				return denied;
			}
			Load();
			return Page();
		}

		public IActionResult OnPostOrg(string slug, string? name)
		{
			IActionResult? denied = RequireAdmin();
			if (denied != null)
			{
				return denied;
			}
			_store.CreateOrg(slug, name);
			return RedirectToPage();
		}

		public IActionResult OnPostUser(string username, string password, long? orgId, string? isAdmin)
		{
			IActionResult? denied = RequireAdmin();
			if (denied != null)
			{
				return denied;
			}
			_store.CreateUser(username, password, orgId, isAdmin == "1");
			return RedirectToPage();
		}

		public IActionResult OnPostDeleteUser(long id)
		{
			IActionResult? denied = RequireAdmin();
			if (denied != null)
			{
				return denied;
			}
			_store.DeleteUser(id);
			return RedirectToPage();
		}

		public IActionResult OnPostPerm(long userId, string repo, string[]? perm)
		{
			IActionResult? denied = RequireAdmin();
			if (denied != null)
			{
				return denied;
			}
			_store.SetPerm(userId, repo, perm ?? Array.Empty<string>());
			return RedirectToPage();
		}

		public IActionResult OnPostCreateToken(long userId, string? name)
		{
			IActionResult? denied = RequireAdmin();
			if (denied != null)
			{
				return denied;
			}
			NewApiKey = _store.CreateApiKey(userId, string.IsNullOrWhiteSpace(name) ? "token" : name.Trim());
			return RedirectToPage();
		}

		public IActionResult OnPostDeleteToken(long id)
		{
			IActionResult? denied = RequireAdmin();
			if (denied != null)
			{
				return denied;
			}
			_store.DeleteApiKey(id);
			return RedirectToPage();
		}

		void Load()
		{
			Orgs = _store.ListOrgs();
			Users = _store.ListUsers();
			Repos = _store.ListRepos();
			Perms = Users.ToDictionary(u => u.Id, u => _store.GetPerms(u.Id));
			ApiKeys = _store.ListApiKeys();
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

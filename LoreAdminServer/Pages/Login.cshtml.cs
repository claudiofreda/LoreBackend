// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using LoreBackend.Auth;
using LoreBackend.Database;
using LoreBackend.Server;

namespace LoreBackend.Pages
{
	[IgnoreAntiforgeryToken]
	public class LoginModel : PageModel
	{
		readonly LoreStore _store;
		readonly SessionStore _sessions;
		readonly LoreOptions _options;
		readonly ILogger<LoginModel> _logger;

		public LoginModel(LoreStore store, SessionStore sessions, IOptions<LoreOptions> options, ILogger<LoginModel> logger)
		{
			_store = store;
			_sessions = sessions;
			_options = options.Value;
			_logger = logger;
		}

		[BindProperty(SupportsGet = true)]
		public string? Session { get; set; }

		public bool OidcEnabled => !string.IsNullOrEmpty(_options.Oidc.ClientId);

		public string? Error { get; private set; }
		public string? SignedInUser { get; private set; }

		public async Task<IActionResult> OnGetAsync()
		{
			if (!OidcEnabled)
			{
				// Local username/password fallback (OIDC not configured).
				return Page();
			}

			// Always run the full OIDC dance. We never trust an existing shim cookie to skip the
			// IdP, otherwise a stale session would reuse stale claims. The `done` marker (set on
			// the post-IdP redirect) distinguishes "start the dance" from "back from the IdP".
			bool returnedFromIdp = Request.Query.ContainsKey("done");
			if (!returnedFromIdp || !(User.Identity?.IsAuthenticated ?? false))
			{
				string redirect = $"/login?session={Uri.EscapeDataString(Session ?? string.Empty)}&done=1";
				return Challenge(new AuthenticationProperties { RedirectUri = redirect }, OpenIdConnectDefaults.AuthenticationScheme);
			}

			// Back from the IdP with a fresh principal: capture current claims, refresh the stored
			// identity, and complete the CLI session.
			List<KeyValuePair<string, string>> claims = User.Claims.Select(c => new KeyValuePair<string, string>(c.Type, c.Value)).ToList();
			string username = First(claims, _options.Oidc.UsernameClaim) ?? First(claims, "sub") ?? "unknown";
			string display = First(claims, _options.Oidc.NameClaim) ?? First(claims, "name") ?? username;
			string preferred = First(claims, "preferred_username") ?? First(claims, "email") ?? username;

			_store.UpsertOidcUser(username);
			_store.UpsertIdentity(username, display, preferred, claims);
			_sessions.Authorize(Session ?? "", username);
			_logger.LogInformation("oidc login as {User} ({Display}) - {Count} claims refreshed", username, display, claims.Count);
			SignedInUser = display;

			return Page();
		}

		public IActionResult OnPost(string username, string password)
		{
			User? user = _store.GetUser(username);
			if (user == null || !LoreStore.VerifyPassword(password, user.PasswordHash))
			{
				Response.StatusCode = 401;
				Error = "Invalid username or password.";
				return Page();
			}
			_sessions.Authorize(Session ?? "", user.Username);
			_logger.LogInformation("interactive login as {User}", user.Username);
			SignedInUser = user.Username;
			return Page();
		}

		static string? First(List<KeyValuePair<string, string>> claims, string type)
		{
			foreach (KeyValuePair<string, string> claim in claims)
			{
				if (string.Equals(claim.Key, type, StringComparison.OrdinalIgnoreCase))
				{
					return claim.Value;
				}
			}

			return null;
		}
	}
}

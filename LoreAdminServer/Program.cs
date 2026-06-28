// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using LoreBackend.Auth;
using LoreBackend.Database;
using LoreBackend.Server;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<LoreOptions>(builder.Configuration.GetSection("Lore"));
builder.Services.PostConfigure<LoreOptions>(options =>
{
    options.SigningKeyPath = Resolve(options.SigningKeyPath);
    options.DatabasePath = Resolve(options.DatabasePath);
});

LoreOptions startupOptions = builder.Configuration.GetSection("Lore").Get<LoreOptions>() ?? new LoreOptions();
bool oidcEnabled = !string.IsNullOrEmpty(startupOptions.Oidc.ClientId);

builder.Services.AddSingleton<AclEngine>();
builder.Services.AddSingleton<LoreStore>();
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton<SessionStore>();
builder.Services.AddGrpc();
builder.Services.AddRazorPages();

// Persist DataProtection keys to a stable, writable location next to the database. The runtime
// image runs as a non-root user whose home (~/.aspnet/DataProtection-Keys) is not writable, so the
// key ring would otherwise be ephemeral - which breaks the OIDC correlation/nonce cookies (they
// can't be decrypted at the callback, surfacing as "Correlation failed"). Keep keys on the same
// persisted volume as the DB so they survive restarts.
string keyRingPath = Path.Combine(Path.GetDirectoryName(Resolve(startupOptions.DatabasePath))!, "dp-keys");
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keyRingPath))
    .SetApplicationName("LoreBackend");

AuthenticationBuilder authentication = builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = oidcEnabled
        ? OpenIdConnectDefaults.AuthenticationScheme
        : CookieAuthenticationDefaults.AuthenticationScheme;
}).AddCookie();

if (oidcEnabled)
{
    authentication.AddOpenIdConnect(options =>
    {
        options.Authority = startupOptions.Oidc.Authority;
        options.ClientId = startupOptions.Oidc.ClientId;
        options.ClientSecret = startupOptions.Oidc.ClientSecret;
        options.ResponseType = "code";
        // Default response mode is form_post, which makes the IdP send the callback as a cross-site
        // POST. SameSite=Lax cookies (see below) are NOT sent on cross-site POSTs, only on top-level
        // GET navigations - so over plain HTTP the correlation cookie wouldn't be attached and the
        // callback fails with "Correlation failed". Using query mode makes the callback a GET redirect
        // that Lax cookies follow. (On HTTPS this is unnecessary, but it's harmless there.)
        options.ResponseMode = "query";
        options.CallbackPath = startupOptions.Oidc.CallbackPath;
        options.SaveTokens = true;
        // Keep raw inbound claim names (sub, groups, roles, ...) so ACL rules match what the IdP emits.
        options.MapInboundClaims = false;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.Scope.Clear();
        foreach (string scope in startupOptions.Oidc.Scopes)
        {
            options.Scope.Add(scope);
        }

        // The correlation/nonce cookies default to SameSite=None, which the browser only keeps
        // when also marked Secure (i.e. over HTTPS). When the dashboard is served over plain HTTP
        // (e.g. on a LAN) those cookies get dropped and the OIDC callback fails with "Correlation
        // failed". The code flow's callback is a top-level GET redirect, so SameSite=Lax is enough,
        // and SameAsRequest lets the cookie work over HTTP while still going Secure over HTTPS.
        options.CorrelationCookie.SameSite = SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.NonceCookie.SameSite = SameSiteMode.Lax;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

        options.TokenValidationParameters.NameClaimType = startupOptions.Oidc.NameClaim;
    });
}

builder.WebHost.ConfigureKestrel(kestrel =>
{
    X509Certificate2 certificate = LoadCertificate(startupOptions);
    kestrel.ListenAnyIP(startupOptions.GrpcPort, listen =>
    {
        listen.Protocols = HttpProtocols.Http2;
        listen.UseHttps(certificate);
    });
    kestrel.ListenAnyIP(startupOptions.HttpPort, listen => listen.Protocols = HttpProtocols.Http1);
});

WebApplication app = builder.Build();
LoreStore store = app.Services.GetRequiredService<LoreStore>();
// Skip the default admin/admin seed in OIDC mode - no local password accounts there.
if (!oidcEnabled)
{
    store.Seed();
}
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.MapGrpcService<UrcAuthService>();
app.MapGrpcService<RebacService>();
app.MapRazorPages();
app.MapGet("/jwks.json", (TokenService tokens) => Results.Json(tokens.GetJwks()));
app.Run();

static X509Certificate2 LoadCertificate(LoreOptions options)
{
    using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(Resolve(options.CertPath), Resolve(options.KeyPath));
    return X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
}

static string Resolve(string path)
{
    return Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);
}
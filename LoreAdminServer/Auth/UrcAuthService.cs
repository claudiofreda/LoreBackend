// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Lore.Proto.Auth;
using LoreBackend.Database;
using LoreBackend.Server;

namespace LoreBackend.Auth
{
    public class UrcAuthService : UrcAuthApi.UrcAuthApiBase
    {
        readonly LoreOptions _options;
        readonly LoreStore _store;
        readonly TokenService _tokens;
        readonly SessionStore _sessions;
        readonly ILogger<UrcAuthService> _logger;

        public UrcAuthService(IOptions<LoreOptions> options, LoreStore store, TokenService tokens, SessionStore sessions, ILogger<UrcAuthService> logger)
        {
            _options = options.Value;
            _store = store;
            _tokens = tokens;
            _sessions = sessions;
            _logger = logger;
        }

        public override Task<HealthCheckResponse> HealthCheck(HealthCheckRequest request, ServerCallContext context)
        {
            return Task.FromResult(new HealthCheckResponse { Status = "ok" });
        }

        public override Task<StartAuthSessionResponse> StartAuthSession(StartAuthSessionRequest request, ServerCallContext context)
        {
            string code = Guid.NewGuid().ToString("N");
            _sessions.Create(code);
            return Task.FromResult(new StartAuthSessionResponse
            {
                SessionCode = code,
                LoginUrl = $"{_options.PublicUrl.TrimEnd('/')}/login?session={code}",
            });
        }

        public override Task<GetAuthSessionResponse> GetAuthSession(GetAuthSessionRequest request, ServerCallContext context)
        {
            SessionStore.Session? session = _sessions.Get(request.SessionCode);
            GetAuthSessionResponse response = new GetAuthSessionResponse();
            if (session != null && session.Authorized && session.Username != null)
            {
                User? user = _store.GetUser(session.Username);
                if (user != null)
                {
                    response.UserToken = MakeUserToken(user);
                }
            }

            return Task.FromResult(response);
        }

        public override async Task<RefreshAuthSessionResponse> RefreshAuthSession(RefreshAuthSessionRequest request, ServerCallContext context)
        {
            User? user = await UserFromAuthAsync(context);
            RefreshAuthSessionResponse response = new RefreshAuthSessionResponse();
            if (user != null)
            {
                response.UserToken = MakeUserToken(user);
            }

            return response;
        }

        public override async Task<VerifyUserResponse> VerifyUser(VerifyUserRequest request, ServerCallContext context)
        {
            return new VerifyUserResponse { UserInfo = Info(await UserFromAuthAsync(context)) };
        }

        public override async Task<ExchangeExternalTokenForUserTokenResponse> ExchangeExternalTokenForUserToken(ExchangeExternalTokenForUserTokenRequest request, ServerCallContext context)
        {
            ExchangeExternalTokenForUserTokenResponse response = new ExchangeExternalTokenForUserTokenResponse();
            User? user;

            // Lore can send arbitrary token type based on user input
            string tokenType = (request.TokenType ?? "").ToLowerInvariant();
            if (tokenType == "api-key")
            {
                // Exchange "api-key" token (issued by our server) for regular session token.
                user = _store.GetUserByApiKey(request.ExternalToken);
            }
            else
            {
                // Fall back to treating the external token as one of our own JWTs.
                string? sub = await _tokens.ValidateAsync(request.ExternalToken);
                user = sub == null ? null : _store.GetUser(sub);
            }

            _logger.LogInformation("ExchangeExternalToken type={Type} user={User}", request.TokenType, user?.Username ?? "(invalid)");
            if (user != null)
            {
                response.UserToken = MakeUserToken(user);
            }

            return response;
        }

        public override Task<ExchangeAPIKeyForUserTokenResponse> ExchangeAPIKeyForUserToken(ExchangeAPIKeyForUserTokenRequest request, ServerCallContext context)
        {
            ExchangeAPIKeyForUserTokenResponse response = new ExchangeAPIKeyForUserTokenResponse();
            User? user = _store.GetUserByApiKey(request.ApiKey);
            _logger.LogInformation("ExchangeAPIKeyForUserToken user={User}", user?.Username ?? "(invalid key)");
            if (user != null)
            {
                response.UserToken = MakeUserToken(user);
            }

            return Task.FromResult(response);
        }

        public override async Task<ExchangeUserTokenForMultiresourceTokenResponse> ExchangeUserTokenForMultiresourceToken(ExchangeUserTokenForMultiresourceTokenRequest request, ServerCallContext context)
        {
            ExchangeUserTokenForMultiresourceTokenResponse response = new ExchangeUserTokenForMultiresourceTokenResponse();
            User? user = await UserFromAuthAsync(context);
            if (user != null)
            {
                response.Token = MakeUserToken(user);
            }

            return response;
        }

        public override async Task<CheckUserPermissionResponse> CheckUserPermission(CheckUserPermissionRequest request, ServerCallContext context)
        {
            User? user = await UserFromAuthAsync(context);
            _logger.LogInformation("CheckUserPermission user={User} resources={Resources}", user?.Username ?? "?", string.Join(",", request.ResourceId));
            CheckUserPermissionResponse response = new CheckUserPermissionResponse();
            if (user != null)
            {
                response.AllowedResourcePermission.Add(ToProto(_store.ResourcesForUser(user)));
            }

            return response;
        }

        public override async Task<LookupUserPermissionsResponse> LookupUserPermissions(LookupUserPermissionsRequest request, ServerCallContext context)
        {
            User? user = await UserFromAuthAsync(context);
            _logger.LogInformation("LookupUserPermissions user={User} filter={Filter}", user?.Username ?? "?", request.ResourceFilter);
            LookupUserPermissionsResponse response = new LookupUserPermissionsResponse();
            if (user != null)
            {
                response.ResourcePermission.Add(ToProto(_store.LookupResourcesForUser(user)));
            }

            return response;
        }

        public override async Task<GetUserInfoResponse> GetUserInfo(GetUserInfoRequest request, ServerCallContext context)
        {
            GetUserInfoResponse response = new GetUserInfoResponse();
            response.UserInfo.Add(Info(await UserFromAuthAsync(context)));
            return response;
        }

        public override async Task<GetUserIdResponse> GetUserId(GetUserIdRequest request, ServerCallContext context)
        {
            return new GetUserIdResponse { UserInfo = Info(await UserFromAuthAsync(context)) };
        }

        public override Task<GetProviderUserIdResponse> GetProviderUserId(GetProviderUserIdRequest request, ServerCallContext context)
        {
            return Task.FromResult(new GetProviderUserIdResponse { UserId = request.UserId, ProviderUserId = request.UserId });
        }

        UserToken MakeUserToken(User user)
        {
            return new UserToken
            {
                UserToken_ = _tokens.MintToken(user),
                ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + _options.TokenLifetimeSeconds,
                UserId = user.Username,
                UserName = user.Username,
            };
        }

        Task<User?> UserFromAuthAsync(ServerCallContext context)
        {
            return _tokens.AuthenticateAsync(context.RequestHeaders.GetValue("authorization"));
        }

        static UserInfo Info(User? user)
        {
            return new UserInfo { UserId = user?.Username ?? "unknown", DisplayName = user?.Username ?? "unknown" };
        }

        static IEnumerable<ResourcePermission> ToProto(IEnumerable<ResourceGrant> grants)
        {
            foreach (ResourceGrant grant in grants)
            {
                ResourcePermission permission = new ResourcePermission { ResourceId = grant.ResourceId };
                permission.Permission.Add(grant.Permission);
                yield return permission;
            }
        }
    }
}
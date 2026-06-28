FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY LoreAdminServer/LoreAdminServer.csproj LoreAdminServer/
RUN dotnet restore LoreAdminServer/LoreAdminServer.csproj

COPY LoreAdminServer/ LoreAdminServer/
RUN dotnet publish LoreAdminServer/LoreAdminServer.csproj -c Release -o /app --no-restore

# ---- runtime image ----
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app

COPY --from=build /app .

# Override any Lore option via env vars using double-underscore notation:
#   Lore__Oidc__ClientId, Lore__Oidc__ClientSecret, Lore__PublicUrl, etc.

EXPOSE 9443 9080

# Certs (server.crt / server.key / jwt-key.b64) and the database must be
# mounted into /app/certs and /app respectively, or paths overridden via env vars:
#   Lore__CertPath, Lore__KeyPath, Lore__SigningKeyPath, Lore__DatabasePath

ENTRYPOINT ["dotnet", "LoreBackend.dll"]

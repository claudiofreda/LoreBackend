// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using LoreBackend.Server;

namespace LoreBackend.Database
{
    public class LoreStore
    {
        public static readonly string[] AllPerms = new[] { "read", "write", "obliterate", "admin", "migrate" };

        readonly string _connectionString;

        public LoreStore(IOptions<LoreOptions> options)
        {
            _connectionString = new SqliteConnectionStringBuilder { DataSource = options.Value.DatabasePath }.ToString();
            using SqliteConnection connection = Open();
            Exec(connection, "PRAGMA journal_mode = WAL");
            Exec(connection, @"
CREATE TABLE IF NOT EXISTS orgs (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  org_id        INTEGER REFERENCES orgs(id) ON DELETE SET NULL,
  is_admin      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS repos (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  lore_id TEXT UNIQUE NOT NULL,
  org_id  INTEGER REFERENCES orgs(id) ON DELETE SET NULL,
  slug    TEXT,
  name    TEXT
);
CREATE TABLE IF NOT EXISTS perms (
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  repo_lore_id TEXT NOT NULL,
  perms        TEXT NOT NULL,
  PRIMARY KEY (user_id, repo_lore_id)
);
CREATE TABLE IF NOT EXISTS api_keys (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name     TEXT NOT NULL,
  key_hash TEXT UNIQUE NOT NULL,
  created  TEXT NOT NULL DEFAULT (datetime('now'))
);");
        }

        SqliteConnection Open()
        {
            SqliteConnection connection = new SqliteConnection(_connectionString);
            connection.Open();
            Exec(connection, "PRAGMA foreign_keys = ON");
            return connection;
        }

        static void Exec(SqliteConnection connection, string sql)
        {
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        static SqliteCommand Cmd(SqliteConnection connection, string sql, params (string, object?)[] args)
        {
            SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            foreach ((string name, object? value) in args)
            {
                command.Parameters.AddWithValue(name, value ?? DBNull.Value);
            }

            return command;
        }

        // ---- password hashing ----
        public static string HashPassword(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
            return Convert.ToHexString(salt).ToLowerInvariant() + ":" + Convert.ToHexString(hash).ToLowerInvariant();
        }

        public static bool VerifyPassword(string password, string stored)
        {
            string[] parts = stored.Split(':');
            if (parts.Length != 2)
            {
                return false;
            }

            byte[] expected = Convert.FromHexString(parts[1]);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromHexString(parts[0]), 100_000, HashAlgorithmName.SHA256, 32);
            return CryptographicOperations.FixedTimeEquals(hash, expected);
        }

        // ---- orgs ----
        public List<Org> ListOrgs()
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT id, slug, name FROM orgs ORDER BY slug");
            using SqliteDataReader reader = command.ExecuteReader();
            List<Org> result = new List<Org>();
            while (reader.Read())
            {
                result.Add(new Org(reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
            }

            return result;
        }

        public Org? GetOrg(long id)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT id, slug, name FROM orgs WHERE id = $id", ("$id", id));
            using SqliteDataReader reader = command.ExecuteReader();
            return reader.Read() ? new Org(reader.GetInt64(0), reader.GetString(1), reader.GetString(2)) : null;
        }

        public Org? GetOrgBySlug(string slug)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT id, slug, name FROM orgs WHERE slug = $slug", ("$slug", slug));
            using SqliteDataReader reader = command.ExecuteReader();
            return reader.Read() ? new Org(reader.GetInt64(0), reader.GetString(1), reader.GetString(2)) : null;
        }

        public Org CreateOrg(string slug, string? name)
        {
            using SqliteConnection connection = Open();
            using (SqliteCommand command = Cmd(connection, "INSERT INTO orgs (slug, name) VALUES ($slug, $name)", ("$slug", slug), ("$name", string.IsNullOrEmpty(name) ? slug : name)))
            {
                command.ExecuteNonQuery();
            }

            return GetOrgBySlug(slug)!;
        }

        // ---- users ----
        public List<User> ListUsers()
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT u.id, u.username, u.password_hash, u.org_id, u.is_admin, o.slug FROM users u LEFT JOIN orgs o ON o.id = u.org_id ORDER BY u.username");
            using SqliteDataReader reader = command.ExecuteReader();
            List<User> result = new List<User>();
            while (reader.Read())
            {
                result.Add(ReadUser(reader));
            }

            return result;
        }

        public User? GetUser(string username)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT u.id, u.username, u.password_hash, u.org_id, u.is_admin, o.slug FROM users u LEFT JOIN orgs o ON o.id = u.org_id WHERE u.username = $u", ("$u", username));
            using SqliteDataReader reader = command.ExecuteReader();
            return reader.Read() ? ReadUser(reader) : null;
        }

        public User CreateUser(string username, string password, long? orgId, bool isAdmin)
        {
            using SqliteConnection connection = Open();
            using (SqliteCommand command = Cmd(connection, "INSERT INTO users (username, password_hash, org_id, is_admin) VALUES ($u, $p, $o, $a)", ("$u", username), ("$p", HashPassword(password)), ("$o", orgId), ("$a", isAdmin ? 1 : 0)))
            {
                command.ExecuteNonQuery();
            }

            return GetUser(username)!;
        }

        public void DeleteUser(long id)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "DELETE FROM users WHERE id = $id", ("$id", id));
            command.ExecuteNonQuery();
        }

        static User ReadUser(SqliteDataReader reader)
        {
            return new User(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetInt64(3),
                reader.GetInt64(4) != 0,
                reader.IsDBNull(5) ? null : reader.GetString(5));
        }

        // ---- repos ----
        public List<Repo> ListRepos()
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT r.id, r.lore_id, r.org_id, r.slug, r.name, o.slug FROM repos r LEFT JOIN orgs o ON o.id = r.org_id ORDER BY r.name");
            using SqliteDataReader reader = command.ExecuteReader();
            List<Repo> result = new List<Repo>();
            while (reader.Read())
            {
                result.Add(new Repo(
                    reader.GetInt64(0),
                    reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetInt64(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.IsDBNull(4) ? reader.GetString(1) : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5)));
            }

            return result;
        }

        public void UpsertRepo(string loreId, long? orgId, string? slug, string name)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection,
                "INSERT INTO repos (lore_id, org_id, slug, name) VALUES ($l, $o, $s, $n) ON CONFLICT(lore_id) DO UPDATE SET org_id=excluded.org_id, slug=excluded.slug, name=excluded.name",
                ("$l", loreId), ("$o", orgId), ("$s", slug), ("$n", string.IsNullOrEmpty(name) ? loreId : name));
            command.ExecuteNonQuery();
        }

        public void DeleteRepo(string loreId)
        {
            using SqliteConnection connection = Open();
            using (SqliteCommand command = Cmd(connection, "DELETE FROM perms WHERE repo_lore_id = $l", ("$l", loreId)))
            {
                command.ExecuteNonQuery();
            }

            using (SqliteCommand command = Cmd(connection, "DELETE FROM repos WHERE lore_id = $l", ("$l", loreId)))
            {
                command.ExecuteNonQuery();
            }
        }

        // ---- permissions ----
        public List<Perm> GetPerms(long userId)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT user_id, repo_lore_id, perms FROM perms WHERE user_id = $u", ("$u", userId));
            using SqliteDataReader reader = command.ExecuteReader();
            List<Perm> result = new List<Perm>();
            while (reader.Read())
            {
                result.Add(new Perm(reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
            }

            return result;
        }

        public void SetPerm(long userId, string repoLoreId, IEnumerable<string> perms)
        {
            string[] clean = perms.Where(p => AllPerms.Contains(p)).Distinct().ToArray();
            using SqliteConnection connection = Open();
            if (clean.Length == 0)
            {
                using SqliteCommand command = Cmd(connection, "DELETE FROM perms WHERE user_id = $u AND repo_lore_id = $r", ("$u", userId), ("$r", repoLoreId));
                command.ExecuteNonQuery();
            }
            else
            {
                using SqliteCommand command = Cmd(connection,
                    "INSERT INTO perms (user_id, repo_lore_id, perms) VALUES ($u, $r, $p) ON CONFLICT(user_id, repo_lore_id) DO UPDATE SET perms=excluded.perms",
                    ("$u", userId), ("$r", repoLoreId), ("$p", string.Join(",", clean)));
                command.ExecuteNonQuery();
            }
        }

        // ---- api keys (non-interactive login) ----
        public string CreateApiKey(long userId, string name)
        {
            string key = "lore_" + Base64Url(RandomNumberGenerator.GetBytes(32));
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "INSERT INTO api_keys (user_id, name, key_hash) VALUES ($u, $n, $h)", ("$u", userId), ("$n", name), ("$h", Sha256Hex(key)));
            command.ExecuteNonQuery();
            return key;
        }

        public List<ApiKey> ListApiKeys()
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT a.id, a.user_id, a.name, a.created, u.username FROM api_keys a JOIN users u ON u.id = a.user_id ORDER BY u.username, a.created");
            using SqliteDataReader reader = command.ExecuteReader();
            List<ApiKey> result = new List<ApiKey>();
            while (reader.Read())
            {
                result.Add(new ApiKey(reader.GetInt64(0), reader.GetInt64(1), reader.GetString(2), reader.GetString(3), reader.GetString(4)));
            }

            return result;
        }

        public void DeleteApiKey(long id)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "DELETE FROM api_keys WHERE id = $id", ("$id", id));
            command.ExecuteNonQuery();
        }

        public User? GetUserByApiKey(string rawKey)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = Cmd(connection, "SELECT u.id, u.username, u.password_hash, u.org_id, u.is_admin, o.slug FROM users u JOIN api_keys a ON a.user_id = u.id LEFT JOIN orgs o ON o.id = u.org_id WHERE a.key_hash = $h", ("$h", Sha256Hex(rawKey)));
            using SqliteDataReader reader = command.ExecuteReader();
            return reader.Read() ? ReadUser(reader) : null;
        }

        static string Sha256Hex(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
        static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        // JWT `resources` claim / permission checks: admins get the urc-* wildcard, others their grants.
        public List<ResourceGrant> ResourcesForUser(User user)
        {
            if (user.IsAdmin)
            {
                return new List<ResourceGrant> { new ResourceGrant("urc-*", AllPerms) };
            }

            return GetPerms(user.Id).Select(p => new ResourceGrant("urc-" + p.RepoLoreId, p.Perms.Split(',', StringSplitOptions.RemoveEmptyEntries))).ToList();
        }

        // Concrete grants for enumeration (LookupUserPermissions): a wildcard cannot be enumerated.
        public List<ResourceGrant> LookupResourcesForUser(User user)
        {
            if (user.IsAdmin)
            {
                return ListRepos().Select(r => new ResourceGrant("urc-" + r.LoreId, AllPerms)).ToList();
            }

            return ResourcesForUser(user);
        }

        public void Seed()
        {
            if (ListUsers().Count == 0)
            {
                Org org = GetOrgBySlug("epic") ?? CreateOrg("epic", "Epic");
                CreateUser("admin", "admin", org.Id, true);
            }
        }
    }
}
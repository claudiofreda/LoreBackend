// Copyright Lukas Jech 2026. All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Options;
using LoreBackend.Database;
using LoreBackend.Server;

namespace LoreBackend.Auth
{
    public class AclEngine
    {
        readonly AclConfig _acl;
        readonly Dictionary<string, HashSet<string>> _profileActions;

        public AclEngine(IOptions<LoreOptions> options)
        {
            _acl = options.Value.Acl;
            _profileActions = FlattenProfiles(_acl.Profiles);
        }

        // Evaluate every entry against the claim set and merge granted actions per resource.
        public List<ResourceGrant> Resolve(IEnumerable<KeyValuePair<string, string>> claims)
        {
            List<KeyValuePair<string, string>> claimList = claims.ToList();
            Dictionary<string, HashSet<string>> merged = new Dictionary<string, HashSet<string>>();

            foreach (AclEntry entry in _acl.Entries)
            {
                if (!HasClaim(claimList, entry.Claim))
                {
                    continue;
                }

                // Compute this entry's granted actions once (direct actions + referenced profiles)...
                HashSet<string> entryActions = new HashSet<string>(entry.Actions.Where(a => LoreStore.AllPerms.Contains(a)));
                foreach (string profileId in entry.Profiles)
                {
                    if (_profileActions.TryGetValue(profileId, out HashSet<string>? profileActions))
                    {
                        entryActions.UnionWith(profileActions);
                    }
                }

                // ...and apply them to every resource the entry targets.
                foreach (string resource in entry.ResourceList())
                {
                    if (!merged.TryGetValue(resource, out HashSet<string>? actions))
                    {
                        actions = new HashSet<string>();
                        merged[resource] = actions;
                    }

                    actions.UnionWith(entryActions);
                }
            }

            return merged
                .Where(kv => kv.Value.Count > 0)
                .Select(kv => new ResourceGrant(kv.Key, kv.Value.ToArray()))
                .ToList();
        }

        // Resolve the set of org slugs granted to the claim-holder. May contain "*" (= all orgs).
        public HashSet<string> ResolveOrgs(IEnumerable<KeyValuePair<string, string>> claims)
        {
            List<KeyValuePair<string, string>> claimList = claims.ToList();
            HashSet<string> orgs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (AclEntry entry in _acl.Entries)
            {
                if (!HasClaim(claimList, entry.Claim))
                {
                    continue;
                }

                foreach (string org in entry.Orgs)
                {
                    orgs.Add(org);
                }
            }

            return orgs;
        }

        // Type comparison is case-insensitive, value exact - matching Horde's ClaimsPrincipal.HasClaim.
        static bool HasClaim(List<KeyValuePair<string, string>> claims, AclClaim claim)
        {
            return claims.Any(c =>
                string.Equals(c.Key, claim.Type, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(c.Value, claim.Value, StringComparison.Ordinal));
        }

        // Resolve each profile's effective action set: union(extends) + actions - excludeActions.
        static Dictionary<string, HashSet<string>> FlattenProfiles(List<AclProfile> profiles)
        {
            Dictionary<string, AclProfile> lookup = new Dictionary<string, AclProfile>(StringComparer.OrdinalIgnoreCase);
            foreach (AclProfile profile in profiles)
            {
                lookup[profile.Id] = profile;
            }

            Dictionary<string, HashSet<string>> computed = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (AclProfile profile in profiles)
            {
                Compute(profile.Id, lookup, computed, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            }

            return computed;
        }

        static HashSet<string> Compute(string id, Dictionary<string, AclProfile> lookup, Dictionary<string, HashSet<string>> computed, HashSet<string> visiting)
        {
            if (computed.TryGetValue(id, out HashSet<string>? existing))
            {
                return existing;
            }

            if (!lookup.TryGetValue(id, out AclProfile? profile))
            {
                throw new InvalidOperationException($"ACL references undefined profile '{id}'");
            }

            if (!visiting.Add(id))
            {
                throw new InvalidOperationException($"Recursive ACL profile definition for '{id}'");
            }

            HashSet<string> actions = new HashSet<string>();
            foreach (string baseId in profile.Extends)
            {
                actions.UnionWith(Compute(baseId, lookup, computed, visiting));
            }

            foreach (string action in profile.Actions)
            {
                actions.Add(action);
            }

            foreach (string action in profile.ExcludeActions)
            {
                actions.Remove(action);
            }

            actions.RemoveWhere(a => !LoreStore.AllPerms.Contains(a));

            visiting.Remove(id);
            computed[id] = actions;
            return actions;
        }
    }
}

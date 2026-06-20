// Copyright Lukas Jech 2026. All Rights Reserved.

using System.Collections.Generic;
using System.Linq;

namespace LoreBackend.Server
{
    public class AclConfig
    {
        public List<AclEntry> Entries { get; set; } = new List<AclEntry>();
        public List<AclProfile> Profiles { get; set; } = new List<AclProfile>();
    }

    // Grants the referenced profiles (and any direct actions) to anyone holding the claim.
    public class AclEntry
    {
        public AclClaim Claim { get; set; } = new AclClaim();
        public List<string> Profiles { get; set; } = new List<string>();
        public List<string> Actions { get; set; } = new List<string>();

        // Resources the granted actions apply to: "urc-*" (all repos) or "urc-<repo-id>". Least
        // privilege: when empty, the entry grants no resources (list "urc-*" explicitly for all).
        public List<string> Resources { get; set; } = new List<string>();

        // De-duplicated resource list - empty when none are set (no resource grant).
        public IEnumerable<string> ResourceList()
        {
            return Resources.Distinct();
        }

        // Organizations granted to claim-holders (OIDC only - parallel to Resources). "*" means all orgs; otherwise a list of org slugs.
        // Empty grants no org membership. Not stored in the DB - org checks resolve against the ACL at request time.
        public List<string> Orgs { get; set; } = new List<string>();
    }

    // A named, reusable bundle of actions. ComputedActions = union(extends) + actions - excludeActions.
    public class AclProfile
    {
        public string Id { get; set; } = "";
        public List<string> Actions { get; set; } = new List<string>();
        public List<string> ExcludeActions { get; set; } = new List<string>();
        public List<string> Extends { get; set; } = new List<string>();
    }

    // Matched against the principal's claims: type case-insensitive, value exact (as Horde does).
    public class AclClaim
    {
        public string Type { get; set; } = "";
        public string Value { get; set; } = "";
    }
}

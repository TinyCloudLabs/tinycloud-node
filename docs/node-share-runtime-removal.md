# Node Share runtime removal

TinyCloud Node exposes only generic capability and storage APIs. Share clients
obtain holder-bound delegations from the standalone Policy Engine and submit
them through `POST /delegate`; encrypted content is read through `POST
/invoke` and decrypted by the browser. Node does not acquire credentials,
evaluate Share policy, issue Share sessions, authorize delivery, or expose any
`/share/*` HTTP route.

The historical Share database migrations and SeaORM entities remain in
`tinycloud-core` as upgrade-compatibility artifacts. Removing already-published
migration identifiers would make existing Node databases unsafe to inspect,
downgrade, or upgrade. Fresh and upgraded databases may therefore contain
unused legacy tables, but production Node code constructs no Share runtime and
never reads or writes them. They can be removed later with an explicit,
forward-only schema retirement migration.

## Delegation-graph compatibility

Older Nodes admitted Share control-plane policy roots into the ordinary
delegation graph and marked each row with the
`xyz.tinycloud.policy/root-profile` fact. Those roots were never ordinary
redelegation authority: only the Share conjunctive session mint, which this
change removes, could draw capabilities from them. An upgraded database still
holds those rows, so `tinycloud-core`'s delegation validator keeps one
surgical guard — a parent carrying that fact is rejected with
`retired-policy-root-cannot-be-ordinary-parent`. Without it, removing the mint
would have widened what an existing database authorizes. Fresh databases never
write the fact, so the guard is inert on new deployments.

Nothing else about generic verification changed: every cited proof must still
resolve, must have delegated to the child's delegator, must be unrevoked and
non-terminal, and must contain the child's capabilities and caveats. The
Share-specific conjunctive path that previously bypassed the delegator-audience
check is gone.

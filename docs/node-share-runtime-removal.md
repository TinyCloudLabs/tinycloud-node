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

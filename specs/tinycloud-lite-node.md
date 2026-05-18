# Spec: TinyCloud Lite Node

**Date:** 2026-04-15
**Status:** Draft
**Name status:** Working name
**Primary goal:** Local-first TinyCloud peer runtime for Node.js and browser environments

---

## 1. Overview

`tinycloud-lite-node` is an embedded TinyCloud peer runtime for local-first applications.

It is intended to let SDK consumers:

- store TinyCloud state locally
- read local canonical state by default
- opt into provisional/local-first reads where needed
- accept local writes while offline
- replicate with TinyCloud replication peers when connectivity is available

It is **not** the same thing as the current `tinycloud-node` server.

The current `tinycloud-node` binary is a full host/server runtime. `tinycloud-lite-node` is a local embedded peer runtime that should eventually be usable from:

- Node.js
- browser environments

This spec is architectural. It exists so the current replication work can be completed in a way that remains compatible with a future lite runtime.

For `tinycloud-lite-node`, this document intentionally narrows the general replica default from the broader replication draft:

- lite-node reads are **canonical by default**
- provisional reads remain available explicitly for local-first behavior

This is a deliberate lite-runtime choice, not an accidental restatement of the broader v2 replica default.

---

## 2. Why This Exists

The replication work already implemented in `tinycloud-node` and `@tinycloud/node-sdk` is building toward local-first replica semantics:

- auth sync
- replication sessions
- KV reconcile and canonical/provisional behavior
- SQL snapshot and changeset replication
- canonical vs provisional SQL state design

But today the actual replicated state machine still lives primarily in the server runtime.

`tinycloud-lite-node` is the missing runtime concept that makes those semantics local and embedded instead of server-only.

This runtime is still a **replica** in the replication model, but it is an embedded local replica rather than a full host.

---

## 3. Relationship To Existing Runtimes

### 3.1 `tinycloud-node`

`tinycloud-node` remains the full host/server runtime.

Responsibilities:

- public HTTP surface
- host or authority-host behavior
- peer-serving replication
- canonical commit assignment where configured
- durable space hosting for networked clients

### 3.2 `tinycloud-lite-node`

`tinycloud-lite-node` is a local embedded peer runtime.

Responsibilities:

- local state storage
- local write buffering
- local canonical and provisional views
- outbound replication
- replay/rebase after canonical sync

It is not required to expose a public network surface in v1.

### 3.3 SDK Wrappers

Current SDK wrappers such as `TinyCloudNode` may later wrap or embed `tinycloud-lite-node`, but that is an implementation choice, not a requirement of this spec.

This spec only defines the lite runtime model.

---

## 4. Runtime Targets

`tinycloud-lite-node` must be designed to run in:

- Node.js
- browser environments

The logical behavior must be the same in both.

### 4.1 Node.js

Expected properties:

- durable filesystem access
- stronger background execution
- easier local SQLite and blob persistence

### 4.2 Browser

Expected properties:

- local durable storage through browser-backed persistence
- no assumption of inbound HTTP serving
- weaker background execution guarantees

The browser runtime must still support the same local-first semantics, but without assuming server-like availability.

---

## 5. Initial Scope

The first version of `tinycloud-lite-node` must support:

- local identity and session handling
- local auth state storage
- authority host bootstrap and canonical position tracking
- local KV state
- local SQLite-backed SQL state
- canonical and provisional reads
- pending local authored facts
- auth sync
- snapshot bootstrap
- replication session open
- notify polling
- KV replication reconcile
- SQL replication reconcile
- local replay/rebuild after canonical advancement

This is sufficient for:

- offline-first local apps
- local writes first, replication later
- reconnect and catch-up

---

## 6. Explicit Non-Goals For V1

The first version of `tinycloud-lite-node` does **not** need to support:

- inbound peer-serving in Node.js
- inbound peer-serving in browser
- authority-host role
- public internet-facing host behavior
- DHT discovery
- Merkle auth proofs
- DuckDB replication
- browser-to-browser direct serving

This is intentional.

V1 should be treated as an **outbound replication runtime**, not a general-purpose public peer host.

Future versions may add serving, but serving is not required to complete the local-first model.

---

## 7. State Model

For each synced space, lite-node stores:

- auth state
- authority/bootstrap metadata
- synced scope declarations
- canonical position metadata
- canonical KV state
- provisional KV state where needed
- canonical SQL state
- provisional SQL state
- pending local authored fact log
- replication metadata and cursors

### 7.1 Canonical State

Canonical state is the local state derived only from accepted canonical replication data.

It is the default read surface.

### 7.2 Provisional State

Provisional state is canonical state plus still-pending local authored facts.

It is used for local-first and offline behavior.

### 7.3 Pending Local Facts

Pending local facts are locally authored operations that are:

- durable
- replayable
- not yet canonically accepted

They must be tracked explicitly rather than inferred from local materialized state.

At minimum, local fact state must support:

- `pending`
- `applied`
- `committed`
- `superseded`
- `rejected`
- `rebase_needed`

---

## 8. Read Model

Lite-node must support two logical read modes:

- `canonical`
- `provisional`

Default read behavior is `canonical`.

Applications that want local-first behavior may opt into `provisional`.

For lite-node, this intentionally overrides the broader replica default in the current replication draft:

- canonical as the safe default
- provisional as the explicit local-first view

---

## 9. Write Model

When offline or before canonical confirmation:

1. local writes append authored facts to the pending local fact log
2. local writes apply to provisional state
3. canonical state remains unchanged

When connectivity is available:

1. lite-node authenticates to a replication peer
2. lite-node syncs auth state and canonical state
3. lite-node rebuilds provisional state from fresh canonical state
4. lite-node replays pending local facts
5. lite-node marks each fact outcome explicitly

Expected fact outcomes include:

- `applied`
- `committed`
- `superseded`
- `rejected`
- `rebase_needed`

The peer runtime, not the end user, owns normal replay and conflict handling.

If a previously local fact later appears in canonical state, lite-node must:

- mark it `committed`
- remove it from the pending replay set
- treat canonical state as the source of truth for its durable effect

Replay and rebase must remain conservative.

In particular:

- stale-schema local facts may be `applied`, `rejected`, or `rebase_needed`
- canonically deleted sensitive rows must never be silently resurrected
- arbitrary SQL conflicts must not be treated as automatically mergeable

---

## 10. Replication Model

V1 lite-node uses **outbound replication only**.

That means it can:

- open replication sessions
- poll notify endpoints
- reconcile KV state
- reconcile SQL state
- exchange auth and authored/canonical facts through the existing replication protocol

Replication peers may include:

- the authority host for a space
- another full host
- a configured replica peer that is allowed to participate in sync

Canonical trust still anchors on the authority host for the space.

That does **not** mean it must:

- listen for inbound replication requests
- expose `peer-serving` endpoints
- advertise itself as a serving replica

This keeps the runtime simple and avoids treating browser or local app runtimes like public servers.

### 10.1 First Sync

Lite-node must support first sync through:

- bootstrap discovery of an authority host or trusted replication peer set
- snapshot bootstrap to a known canonical position
- replay of later canonical changes after the snapshot base

Initial sync is not complete without a canonical base position.

### 10.2 Scope Model

Lite-node is not required to replicate whole spaces only.

It must be compatible with the scope model already used by the replication protocol:

- KV path-prefix scopes
- SQL whole-database scopes
- SQL table scopes
- SQL table plus primary-key range or prefix scopes where supported

The lite runtime may choose smaller local replica scopes, but it must not assume only whole-space replication.

---

## 11. Storage Model

### 11.1 General Principle

`tinycloud-lite-node` must preserve TinyCloud logical storage semantics, but it does **not** need to reuse the exact same storage implementation or filesystem layout as `tinycloud-node`.

The important requirement is semantic compatibility, not byte-for-byte storage parity.

### 11.2 KV and Blob Data

Lite-node does need a local durable store for KV values and any block/blob-backed content it chooses to retain locally.

However:

- V1 does not require it to expose the full host block store model publicly
- V1 does not require storage layout parity with `tinycloud-node`
- V1 may use a simpler embedded storage adapter per runtime

So the rule is:

- **logical blob/value persistence is required**
- **full host block-store parity is not required**

This keeps the design open for:

- filesystem-backed local stores in Node.js
- OPFS or IndexedDB-backed stores in browser
- later optimization or unification without blocking the first lite runtime

### 11.3 SQL Storage

For SQL, lite-node should follow the canonical/provisional split already specified in the SQL replication follow-on work:

- canonical SQL store
- provisional SQL store
- durable pending local SQL fact log
- metadata store

This is the intended long-term shape for SQL in any local-first runtime.

---

## 12. Canonical vs Provisional In Main Nodes

Canonical vs provisional state is primarily a **replica/lite-node concern**, not the default public read model for full hosts.

### 12.1 Authority Hosts

Authority hosts should generally serve canonical state.

They are the source of canonical ordering, so exposing provisional local state as the normal host read surface is unnecessary and undesirable.

### 12.2 Non-Authority Full Hosts

Non-authority full hosts may still need internal authored/pending state for replication mechanics, but they do not need to expose provisional reads as the default public service model.

### 12.3 Lite Nodes and Replicas

Lite nodes and explicit replica runtimes are where canonical/provisional split matters most:

- they may author offline
- they may diverge locally for a while
- they need local-first reads without pretending those reads are canonical truth

So the intended rule is:

- full hosts: canonical by default, provisional mostly internal if present at all
- lite nodes and replicas: canonical plus provisional as first-class local runtime semantics

---

## 13. Security and Trust Model

`tinycloud-lite-node` must use the same core trust model as the replication protocol:

- auth sync is required for independent validation
- replication sessions are scoped and authenticated
- canonical order comes from authority hosts
- local authored facts are real facts but not automatically canonical truth

It must not treat `/info` or peer runtime claims as authoritative for space-scoped truth.

Authority/bootstrap trust must come from:

- signed bootstrap metadata
- validated delegation state
- other space-scoped proof material already recognized by the replication protocol

Lite-node must not assume trust-the-host in the same way an ephemeral browser client might.

It is a local peer runtime, not just a thin remote client.

---

## 14. Browser and Node.js Differences

### 14.1 Shared Semantics

Both runtimes must support:

- local pending facts
- canonical/provisional reads
- auth sync
- notify/reconcile
- replay after canonical advancement

### 14.2 Node.js Advantages

Node.js is the easier first target for a richer lite runtime because it has:

- better background execution
- simpler durable storage
- a more natural path to future peer-serving if desired

### 14.3 Browser Constraints

Browser lite-node should remain outbound-only in v1 because browsers do not naturally behave like public hosts.

Constraints include:

- no inbound HTTP listener
- background execution limits
- storage quota and persistence differences

The browser runtime is still useful as a local-first peer, just not as a serving host in v1.

---

## 15. Build-With-This-In-Mind Constraints

Current replication work in `tinycloud-node` should remain compatible with a future lite runtime.

That means:

- replication protocol choices should avoid unnecessary server-only assumptions
- canonical/provisional logic should not be tied only to public host surfaces
- SQL state split work should be reusable in an embedded runtime
- KV and SQL reconcile logic should be expressible as local runtime operations, not only HTTP server behaviors

This spec is meant to shape current implementation choices even before lite-node exists.

---

## 16. Phased Adoption

### Phase 1

Treat `tinycloud-lite-node` as an architectural target only.

Use it to guide:

- replication protocol shape
- SQL canonical/provisional implementation
- SDK API design

### Phase 2

Implement a Node.js lite runtime first.

This is the lowest-friction path to proving:

- local persistence
- canonical/provisional behavior
- offline writes
- replay/rebase

### Phase 3

Implement a browser lite runtime with the same semantics but browser-appropriate storage and lifecycle constraints.

Serving remains out of scope unless re-scoped later.

---

## 17. Normative Summary

1. `tinycloud-lite-node` is a local embedded peer runtime, not a full host.
2. It must support local canonical and provisional state.
3. It must support pending local authored facts and replay after canonical sync.
4. Default reads must be canonical.
5. It must support snapshot bootstrap and canonical position tracking for first sync.
6. V1 does not require peer-serving for either Node.js or browser runtimes.
7. Lite-node must preserve TinyCloud logical storage semantics, but does not need exact storage implementation parity with full hosts.
8. Lite-node must support scoped replication rather than assuming only whole-space sync.
9. Canonical vs provisional state is primarily a lite-node and replica concern, not the normal public read model for authority hosts.

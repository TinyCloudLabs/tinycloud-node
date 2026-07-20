//! P2 (compute-service.md §8/§9/§9.1/§9.1.1/§10, plan P2): the in-node
//! `WasmtimeBackend` + the host mediator that turns each of the guest's four
//! host imports into a fully-authorized, journaled data operation.
//!
//! Lives entirely in the SERVER crate (plan P2: "the injected
//! internal-invocation executor is composed in the server crate") because it
//! must reach BOTH `SpaceDatabase::invoke` (KV, core) and `SqlService` (SQL,
//! server-only) -- neither is reachable from `tinycloud-core` alone
//! (`SqlService` lives behind the route layer).
//!
//! ## Pinned ABI (compute-service.md §9.1, Appendix A.2 -- NORMATIVE)
//!
//! * core module (not a component);
//! * guest exports `alloc(len: i32) -> ptr: i32` and
//!   `run(ptr: i32, len: i32) -> (ptr: i32, len: i32)`;
//! * four host imports, module name `"tinycloud"`, each
//!   `(ptr: i32, len: i32) -> (ptr: i32, len: i32)`: `storage_get`,
//!   `storage_put`, `storage_del`, `sql_query`;
//! * every payload crossing the boundary is JSON bytes.
//!
//! ## Denial contract (Appendix A.4 -- NORMATIVE)
//!
//! A host call for an ability the selected `D_fn` does not grant returns an
//! `{"ok":false,"error":{...}}` envelope INTO GUEST MEMORY and does NOT trap
//! the guest and does NOT perform the underlying operation. A guest that
//! imports a function outside the four-function `"tinycloud"` surface fails
//! at module INSTANTIATION (a link error) -- a distinct, separately-tested
//! condition (§10.1 "forbidden import").

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use futures::io::AsyncWriteExt;
use wasmtime::{Caller, Config as WasmConfig, Engine, FuncType, Linker, Module, Store, Val, ValType};

use tinycloud_auth::{
    authorization::{Cid as AuthCid, TinyCloudInvocation},
    resource::{Path as AuthPath, Service as AuthService, SpaceId},
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::JWK,
        ucan::Payload,
    },
    ucan_capabilities_object::{Ability as UcanAbility, Capabilities},
};
use tinycloud_core::{
    compute::compute_function_binding_notabene,
    db::TxError,
    events::Invocation,
    hash::Hash,
    models::invocation::InvocationError,
    sql::{SqlRequest, SqlResponse, SqlService},
    storage::ImmutableStaging,
    types::{Metadata, Resource},
    ComputeGrantedAbility, InvocationOutcome, KvInvokeOptions, TxStoreError,
};

use crate::config::ComputeStorageConfig;
use crate::{BlockStage, BlockStores, TinyCloud};

const KV_GET: &str = "tinycloud.kv/get";
const KV_PUT: &str = "tinycloud.kv/put";
const KV_DEL: &str = "tinycloud.kv/del";
const SQL_READ: &str = "tinycloud.sql/read";
const SQL_WRITE: &str = "tinycloud.sql/write";
/// The fixed SQL database name the compute host surface targets
/// (compute-service.md Appendix A.1: `resource path: db`). A compute
/// routine's SQL host import always operates on this single, per-space,
/// per-routine-identity database -- a convention this implementation
/// defines (the wire format does not carry a `db_name` for compute SQL
/// calls), matching the pinned conformance fixture exactly.
const COMPUTE_SQL_DB_NAME: &str = "db";

/// One journal entry (compute-service.md §9.1.1). `bytes_in`/`bytes_out` are
/// the JSON byte lengths AT THE ABI BOUNDARY (the host import's argument and
/// return bytes) -- NOT the underlying KV value size -- so they are
/// deterministic and computable without touching storage internals.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEntry {
    pub resource: String,
    pub ability: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub destination: String,
    pub granted: bool,
}

/// The execution manifest (compute-service.md §9.1.1): the full per-call
/// journal plus the granted-vs-exercised capability sets -- the
/// "permission observability" scope-down signal.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionManifest {
    pub calls: Vec<ManifestEntry>,
    pub granted: BTreeSet<String>,
    pub exercised: BTreeSet<String>,
    pub granted_but_unexercised: BTreeSet<String>,
}

impl ExecutionManifest {
    fn record(&mut self, entry: ManifestEntry) {
        if entry.granted {
            self.exercised.insert(entry.ability.clone());
        }
        self.calls.push(entry);
    }

    fn finalize(mut self) -> Self {
        self.granted_but_unexercised = self
            .granted
            .difference(&self.exercised)
            .cloned()
            .collect();
        self
    }
}

/// P2 top-level compute-execute error. Every variant maps to a DISTINCT HTTP
/// status in `routes/mod.rs` -- in particular `RoutineIdentityRotated` MUST
/// map to 409/503, NEVER 403 (compute-service.md §6.2/F1.5), and is
/// distinct from an authorization denial, which never reaches this type at
/// all (host-call denials are the A.4 envelope, not a `ComputeExecError`).
#[derive(Debug, thiserror::Error)]
pub enum ComputeExecError {
    #[error("no compute function deployed at \"{0}\" in this space")]
    FunctionNotFound(String),
    #[error("content_cid pin mismatch: pinned {expected}, deployed {actual}")]
    ContentCidMismatch { expected: String, actual: String },
    #[error("routine-identity-rotated: re-derived routine DID does not match the deployed D_fn's delegatee for content_cid {0}; re-deploy to re-mint D_fn")]
    RoutineIdentityRotated(String),
    #[error("function \"{0}\" is not in the caller's functions allowlist")]
    FunctionNotAllowed(String),
    #[error("input failed schema validation: {0}")]
    InputSchemaInvalid(String),
    #[error("caveat {name} = {value} exceeds the configured ceiling {ceiling}")]
    CaveatCeilingExceeded {
        name: &'static str,
        value: u64,
        ceiling: u64,
    },
    #[error("wasm module error: {0}")]
    Module(String),
    #[error("execution trapped: {0}")]
    Trap(String),
    #[error(transparent)]
    Db(#[from] tinycloud_core::sea_orm::DbErr),
    #[error(transparent)]
    Artifact(#[from] tinycloud_core::database_artifacts::DatabaseArtifactError),
    #[error("internal compute error: {0}")]
    Internal(String),
}

/// `.manage()`d alongside `ComputeService` (compute-service.md §9.1, plan
/// P2). Holds the wasmtime `Engine` (fuel + epoch interruption enabled) and
/// the numeric-ceiling config. One `Engine` per node process; a background
/// task increments its epoch on a fixed tick so `maxDuration` caveats are
/// enforceable via epoch interruption (§10.1).
pub struct ComputeExecutor {
    engine: Engine,
    config: ComputeStorageConfig,
}

/// How often the epoch ticker increments the engine's epoch. `maxDuration`
/// caveats are quantized to this granularity.
const EPOCH_TICK: Duration = Duration::from_millis(20);
/// Fuel units consumed per millisecond of `maxDuration`, used to derive a
/// fuel budget from the duration caveat as belt-and-braces CPU metering
/// (§10.1 "CPU budget ... bound total work (belt-and-braces with
/// maxDuration)"). `ComputeCaveats` has no standalone CPU field.
const FUEL_PER_MS: u64 = 5_000_000;

impl ComputeExecutor {
    pub fn new(config: ComputeStorageConfig) -> anyhow::Result<Self> {
        let mut wasm_config = WasmConfig::new();
        wasm_config.consume_fuel(true);
        wasm_config.epoch_interruption(true);
        wasm_config.async_support(true);
        let engine = Engine::new(&wasm_config)?;
        let ticker_engine = engine.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(EPOCH_TICK).await;
                ticker_engine.increment_epoch();
            }
        });
        Ok(Self { engine, config })
    }

    pub fn config(&self) -> &ComputeStorageConfig {
        &self.config
    }
}

/// The immutable, per-execution context shared by every host import call
/// (cloned cheaply -- an `Arc` -- into each `'static` wasmtime host closure).
struct ExecutionCtx {
    tinycloud: TinyCloud,
    sql_service: SqlService,
    staging: BlockStage,
    space: SpaceId,
    content_cid: String,
    routine_did: String,
    routine_vm: String,
    routine_jwk: JWK,
    /// The distinct `D_fn` delegation hashes cited as parents on every
    /// internal invocation (compute-service.md §5.1/F5, cite-all).
    parents: Vec<Hash>,
}

/// Per-execution, mutable wasmtime `Store` data.
struct GuestState {
    limits: wasmtime::StoreLimits,
    manifest: ExecutionManifest,
}

impl wasmtime::ResourceLimiter for GuestState {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.limits.memory_growing(current, desired, maximum)
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.limits.table_growing(current, desired, maximum)
    }
}

/// The result of resolving `(space, function)` -> a loaded artifact + its
/// cite-all `D_fn` candidate set, INCLUDING the routine-identity-rotated
/// tripwire (§6.2/F1.5).
pub struct ResolvedFunction {
    pub wasm: Vec<u8>,
    pub content_cid: String,
    pub routine_did: String,
    pub routine_vm: String,
    pub routine_jwk: JWK,
    pub granted: Vec<ComputeGrantedAbility>,
}

/// Resolve `(space, function)` to a loaded artifact and its `D_fn` grant set,
/// applying the F1.5 rotation tripwire. Split out from `execute` so the
/// tripwire is independently testable (compute_execute.rs).
pub async fn resolve_function(
    tinycloud: &TinyCloud,
    compute_service: &tinycloud_core::compute::ComputeService,
    space: &SpaceId,
    function: &str,
    content_cid_pin: Option<&str>,
) -> Result<ResolvedFunction, ComputeExecError> {
    let artifact = tinycloud
        .load_compute_artifact(&space.to_string(), function)
        .await?
        .ok_or_else(|| ComputeExecError::FunctionNotFound(function.to_string()))?;

    if let Some(pin) = content_cid_pin {
        if pin != artifact.content_hash {
            return Err(ComputeExecError::ContentCidMismatch {
                expected: pin.to_string(),
                actual: artifact.content_hash,
            });
        }
    }

    let content_cid = artifact.content_hash.clone();

    // F1.5 tripwire: re-derive the routine key for (space, artifact CID) and
    // find the D_fn candidates bound to THAT identity right now.
    let routine_did = compute_service
        .routine_key_deriver()
        .derive_routine_did(space, &content_cid)
        .await
        .map_err(|e| ComputeExecError::Internal(e.to_string()))?;

    let granted = tinycloud
        .compute_granted_abilities(&routine_did, space)
        .await?;

    if granted.is_empty() {
        // Disambiguate "never granted" from "granted under a now-rotated
        // identity" (§6.2/F1.5) via the binding-caveat scan -- a D_fn for
        // THIS content_cid exists under SOME other delegatee.
        if let Some(other_delegatee) = tinycloud
            .compute_delegatee_for_binding(space, &content_cid)
            .await?
        {
            if other_delegatee != routine_did {
                return Err(ComputeExecError::RoutineIdentityRotated(content_cid));
            }
        }
        return Err(ComputeExecError::FunctionNotFound(function.to_string()));
    }

    let seed = compute_service
        .routine_key_deriver()
        .derive_routine_seed(space, &content_cid)
        .await
        .map_err(|e| ComputeExecError::Internal(e.to_string()))?;
    let routine_jwk = tinycloud_core::compute::routine_jwk_from_seed(seed)
        .map_err(|e| ComputeExecError::Internal(e.to_string()))?;
    let routine_vm = format!(
        "{routine_did}#{}",
        routine_did
            .rsplit_once(':')
            .map(|(_, frag)| frag)
            .unwrap_or_default()
    );

    Ok(ResolvedFunction {
        wasm: artifact.payload,
        content_cid,
        routine_did,
        routine_vm,
        routine_jwk,
        granted,
    })
}

/// The full P2 execute entrypoint: instantiate the resolved function under
/// `caveats`, run it against `input`, and return the guest's result +
/// execution manifest.
#[allow(clippy::too_many_arguments)]
pub async fn execute(
    executor: &ComputeExecutor,
    tinycloud: &TinyCloud,
    sql_service: &SqlService,
    staging: &BlockStage,
    resolved: ResolvedFunction,
    space: &SpaceId,
    input: serde_json::Value,
    caveats: &tinycloud_core::compute::ComputeCaveats,
) -> Result<(serde_json::Value, ExecutionManifest), ComputeExecError> {
    // §10.1 numeric ceilings: reject (not silently clamp) an absurd caveat on
    // ingest.
    let cfg = executor.config();
    let max_duration_ms = match caveats.max_duration {
        Some(v) if v > cfg.max_duration_ms_ceiling => {
            return Err(ComputeExecError::CaveatCeilingExceeded {
                name: "maxDuration",
                value: v,
                ceiling: cfg.max_duration_ms_ceiling,
            })
        }
        Some(v) => v,
        None => cfg.default_max_duration_ms,
    };
    let max_memory_bytes = match caveats.max_memory {
        Some(v) if v > cfg.max_memory_bytes_ceiling => {
            return Err(ComputeExecError::CaveatCeilingExceeded {
                name: "maxMemory",
                value: v,
                ceiling: cfg.max_memory_bytes_ceiling,
            })
        }
        Some(v) => v,
        None => cfg.default_max_memory_bytes,
    };

    if let Some(schema) = &caveats.inputs {
        validate_input_schema(schema, &input)
            .map_err(ComputeExecError::InputSchemaInvalid)?;
    }

    let granted_abilities: BTreeSet<String> = resolved
        .granted
        .iter()
        .map(|g| g.ability.to_string())
        .collect();
    let parents: Vec<Hash> = {
        let mut seen = BTreeSet::new();
        resolved
            .granted
            .iter()
            .filter(|g| seen.insert(g.delegation))
            .map(|g| g.delegation)
            .collect()
    };

    let ctx = Arc::new(ExecutionCtx {
        tinycloud: tinycloud.clone(),
        sql_service: sql_service.clone(),
        staging: staging.clone(),
        space: space.clone(),
        content_cid: resolved.content_cid.clone(),
        routine_did: resolved.routine_did.clone(),
        routine_vm: resolved.routine_vm.clone(),
        routine_jwk: resolved.routine_jwk.clone(),
        parents,
    });

    let module = Module::new(&executor.engine, &resolved.wasm)
        .map_err(|e| ComputeExecError::Module(e.to_string()))?;

    let mut linker: Linker<GuestState> = Linker::new(&executor.engine);
    register_host_imports(&mut linker, ctx.clone());

    let limits = wasmtime::StoreLimitsBuilder::new()
        .memory_size(max_memory_bytes as usize)
        .build();
    let mut store = Store::new(
        &executor.engine,
        GuestState {
            limits,
            manifest: ExecutionManifest {
                granted: granted_abilities,
                ..Default::default()
            },
        },
    );
    store.limiter(|state| &mut state.limits);

    let fuel_budget = max_duration_ms.saturating_mul(FUEL_PER_MS).min(cfg.max_fuel_ceiling);
    store
        .set_fuel(fuel_budget)
        .map_err(|e| ComputeExecError::Internal(e.to_string()))?;
    // Epoch deadline: one tick per ~EPOCH_TICK of wall time, rounded up.
    let deadline_ticks = (max_duration_ms / EPOCH_TICK.as_millis() as u64).max(1);
    store.set_epoch_deadline(deadline_ticks);

    let instance = linker
        .instantiate_async(&mut store, &module)
        .await
        .map_err(|e| ComputeExecError::Module(e.to_string()))?;

    let functions_allowed = caveats
        .functions
        .as_ref()
        .map(|allowlist| allowlist.iter().any(|f| f == &resolved_function_name(&ctx)))
        .unwrap_or(true);
    if !functions_allowed {
        return Err(ComputeExecError::FunctionNotAllowed(
            resolved_function_name(&ctx),
        ));
    }

    let alloc = instance
        .get_func(&mut store, "alloc")
        .ok_or_else(|| ComputeExecError::Module("guest is missing the \"alloc\" export".into()))?;
    let run = instance
        .get_func(&mut store, "run")
        .ok_or_else(|| ComputeExecError::Module("guest is missing the \"run\" export".into()))?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| ComputeExecError::Module("guest is missing the \"memory\" export".into()))?;

    let input_bytes = serde_json::to_vec(&input).map_err(|e| ComputeExecError::Internal(e.to_string()))?;
    let input_ptr = call_alloc(&mut store, alloc, input_bytes.len())
        .await
        .map_err(map_trap)?;
    memory
        .write(&mut store, input_ptr as usize, &input_bytes)
        .map_err(|e| ComputeExecError::Internal(e.to_string()))?;

    let mut run_results = [Val::I32(0), Val::I32(0)];
    run.call_async(
        &mut store,
        &[Val::I32(input_ptr), Val::I32(input_bytes.len() as i32)],
        &mut run_results,
    )
    .await
    .map_err(map_trap)?;

    let result_ptr = run_results[0].unwrap_i32() as usize;
    let result_len = run_results[1].unwrap_i32() as usize;
    let mut result_bytes = vec![0u8; result_len];
    memory
        .read(&mut store, result_ptr, &mut result_bytes)
        .map_err(|e| ComputeExecError::Internal(e.to_string()))?;
    let result: serde_json::Value =
        serde_json::from_slice(&result_bytes).map_err(|e| ComputeExecError::Internal(e.to_string()))?;

    let manifest = std::mem::take(&mut store.data_mut().manifest).finalize();
    Ok((result, manifest))
}

fn resolved_function_name(ctx: &ExecutionCtx) -> String {
    // The allowlist is keyed on the `<function-path>` name; the mediator
    // only ever has the content CID in hand at this layer, so callers that
    // need name-based allowlisting pass it through `caveats.functions`
    // against the ORIGINAL request's `function` field (checked by the
    // route handler, not here, when the name is available). This helper
    // exists so `execute`'s allowlist check has a stable, single call site
    // to extend if/when the name is threaded into `ExecutionCtx`.
    ctx.content_cid.clone()
}

async fn call_alloc(
    store: &mut Store<GuestState>,
    alloc: wasmtime::Func,
    len: usize,
) -> Result<i32, wasmtime::Error> {
    let mut results = [Val::I32(0)];
    alloc
        .call_async(&mut *store, &[Val::I32(len as i32)], &mut results)
        .await?;
    Ok(results[0].unwrap_i32())
}

fn map_trap(e: wasmtime::Error) -> ComputeExecError {
    ComputeExecError::Trap(e.to_string())
}

fn register_host_imports(linker: &mut Linker<GuestState>, ctx: Arc<ExecutionCtx>) {
    let engine = linker.engine().clone();
    let ty = FuncType::new(
        &engine,
        [ValType::I32, ValType::I32],
        [ValType::I32, ValType::I32],
    );

    for (name, ability_kind) in [
        ("storage_get", HostCall::Get),
        ("storage_put", HostCall::Put),
        ("storage_del", HostCall::Del),
        ("sql_query", HostCall::Sql),
    ] {
        let ctx = ctx.clone();
        let ty = ty.clone();
        linker
            .func_new_async("tinycloud", name, ty, move |mut caller, params, results| {
                let ctx = ctx.clone();
                Box::new(async move {
                    let ptr = params[0].unwrap_i32();
                    let len = params[1].unwrap_i32();
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                        .ok_or_else(|| wasmtime::Error::msg("guest has no \"memory\" export"))?;
                    let mut arg_bytes = vec![0u8; len as usize];
                    memory.read(&mut caller, ptr as usize, &mut arg_bytes)?;

                    let (response_bytes, entry) =
                        handle_host_call(&ctx, ability_kind, &arg_bytes).await?;

                    let alloc = caller
                        .get_export("alloc")
                        .and_then(|e| e.into_func())
                        .ok_or_else(|| wasmtime::Error::msg("guest has no \"alloc\" export"))?;
                    let mut alloc_results = [Val::I32(0)];
                    alloc
                        .call_async(
                            &mut caller,
                            &[Val::I32(response_bytes.len() as i32)],
                            &mut alloc_results,
                        )
                        .await?;
                    let response_ptr = alloc_results[0].unwrap_i32();
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                        .ok_or_else(|| wasmtime::Error::msg("guest has no \"memory\" export"))?;
                    memory.write(&mut caller, response_ptr as usize, &response_bytes)?;

                    caller.data_mut().manifest.record(entry);

                    results[0] = Val::I32(response_ptr);
                    results[1] = Val::I32(response_bytes.len() as i32);
                    Ok(())
                })
            })
            .expect("registering a tinycloud host import must not fail");
    }
}

#[derive(Clone, Copy)]
enum HostCall {
    Get,
    Put,
    Del,
    Sql,
}

/// Dispatch one host call: mediate (mint + submit the internal invocation),
/// build the guest-facing JSON envelope, and produce the manifest entry.
/// Returns `Err` ONLY for genuine infrastructure failures (aborts the whole
/// execution as a trap) -- an authorization denial is Ok(...) carrying the
/// A.4 envelope, never an Err (compute-service.md Appendix A.4: "does NOT
/// trap the guest").
async fn handle_host_call(
    ctx: &ExecutionCtx,
    call: HostCall,
    arg_bytes: &[u8],
) -> Result<(Vec<u8>, ManifestEntry), wasmtime::Error> {
    let bytes_in = arg_bytes.len() as u64;
    match call {
        HostCall::Get | HostCall::Put | HostCall::Del => {
            #[derive(serde::Deserialize)]
            struct KvArg {
                key: String,
                #[serde(default)]
                value: Option<String>,
            }
            let arg: KvArg = serde_json::from_slice(arg_bytes)
                .map_err(|e| wasmtime::Error::msg(format!("invalid storage arg JSON: {e}")))?;
            let ability = match call {
                HostCall::Get => KV_GET,
                HostCall::Put => KV_PUT,
                HostCall::Del => KV_DEL,
                HostCall::Sql => unreachable!(),
            };
            let put_bytes = matches!(call, HostCall::Put).then(|| {
                arg.value.clone().unwrap_or_default().into_bytes()
            });
            let outcome = mediate_kv_call(ctx, ability, &arg.key, put_bytes)
                .await
                .map_err(|e| wasmtime::Error::msg(e.to_string()))?;
            let (envelope, granted, destination) = match outcome {
                KvOutcome::ReadOk(Some(bytes)) => (
                    serde_json::json!({"ok": true, "value": String::from_utf8_lossy(&bytes)}),
                    true,
                    "inline".to_string(),
                ),
                KvOutcome::ReadOk(None) => (
                    serde_json::json!({"ok": true, "value": null}),
                    true,
                    "inline".to_string(),
                ),
                KvOutcome::WriteOk => (
                    serde_json::json!({"ok": true}),
                    true,
                    arg.key.clone(),
                ),
                KvOutcome::DeleteOk => (
                    serde_json::json!({"ok": true}),
                    true,
                    arg.key.clone(),
                ),
                KvOutcome::Denied { ability, resource } => (
                    serde_json::json!({
                        "ok": false,
                        "error": {
                            "code": "ability-denied",
                            "ability": ability,
                            "resource": resource,
                        }
                    }),
                    false,
                    String::new(),
                ),
            };
            let response_bytes = serde_json::to_vec(&envelope)
                .map_err(|e| wasmtime::Error::msg(e.to_string()))?;
            let resource_str = kv_resource_string(&ctx.space, &arg.key);
            let entry = ManifestEntry {
                resource: resource_str,
                ability: ability.to_string(),
                bytes_in,
                bytes_out: response_bytes.len() as u64,
                destination,
                granted,
            };
            Ok((response_bytes, entry))
        }
        HostCall::Sql => {
            let sql_request: SqlRequest = serde_json::from_slice(arg_bytes)
                .map_err(|e| wasmtime::Error::msg(format!("invalid sql_query arg JSON: {e}")))?;
            let ability = sql_ability(&sql_request);
            let outcome = mediate_sql_call(ctx, ability, sql_request)
                .await
                .map_err(|e| wasmtime::Error::msg(e.to_string()))?;
            let (envelope, granted) = match outcome {
                SqlOutcome::Ok(response) => (
                    serde_json::to_value(response).map_err(|e| wasmtime::Error::msg(e.to_string()))?,
                    true,
                ),
                SqlOutcome::Denied { ability, resource } => (
                    serde_json::json!({
                        "ok": false,
                        "error": {
                            "code": "ability-denied",
                            "ability": ability,
                            "resource": resource,
                        }
                    }),
                    false,
                ),
            };
            let response_bytes = serde_json::to_vec(&envelope)
                .map_err(|e| wasmtime::Error::msg(e.to_string()))?;
            let resource_str = format!("{}/sql/{}", ctx.space, COMPUTE_SQL_DB_NAME);
            let entry = ManifestEntry {
                resource: resource_str,
                ability: ability.to_string(),
                bytes_in,
                bytes_out: response_bytes.len() as u64,
                destination: "inline".to_string(),
                granted,
            };
            Ok((response_bytes, entry))
        }
    }
}

fn sql_ability(request: &SqlRequest) -> &'static str {
    match request {
        SqlRequest::Query { .. } | SqlRequest::Export => SQL_READ,
        SqlRequest::Execute { .. } | SqlRequest::Batch { .. } | SqlRequest::ExecuteStatement { .. } => {
            SQL_WRITE
        }
    }
}

fn kv_resource_string(space: &SpaceId, key: &str) -> String {
    format!("{space}/kv/{key}")
}

enum KvOutcome {
    ReadOk(Option<Vec<u8>>),
    WriteOk,
    DeleteOk,
    Denied { ability: String, resource: String },
}

enum SqlOutcome {
    Ok(SqlResponse),
    Denied { ability: String, resource: String },
}

/// Mint an internal invocation SIGNED BY THE ROUTINE KEY, citing every
/// candidate `D_fn` as a parent (cite-all, §5.1/F5), echoing `D_fn`'s
/// `computeFunctionBinding` caveat VERBATIM (§6.2/F1 -- the byte-equality
/// echo rule), and run it through the SAME `validate()`/`save()` path every
/// other invocation uses. No new authorization-engine code: a denial here is
/// `validate()`'s existing `UnauthorizedAction`/`MissingParents`/
/// `CaveatsNotContained` outcome, translated into the A.4 envelope by the
/// caller.
async fn mediate_kv_call(
    ctx: &ExecutionCtx,
    ability: &str,
    key: &str,
    put_bytes: Option<Vec<u8>>,
) -> Result<KvOutcome, ComputeExecError> {
    let path: AuthPath = key
        .parse()
        .map_err(|e: tinycloud_auth::resource::KRIParseError| {
            ComputeExecError::Internal(format!("invalid kv key {key}: {e:?}"))
        })?;
    let resource_id = ctx
        .space
        .clone()
        .to_resource(
            "kv".parse::<AuthService>().expect("\"kv\" is a valid service"),
            Some(path.clone()),
            None,
            None,
        );
    let resource_str = resource_id.to_string();

    let invocation = mint_internal_invocation(ctx, &resource_id, ability)?;

    let mut inputs: std::collections::HashMap<
        (SpaceId, AuthPath),
        (Metadata, tinycloud_core::storage::HashBuffer<<BlockStage as ImmutableStaging>::Writable>),
    > = std::collections::HashMap::new();
    if let Some(bytes) = &put_bytes {
        let mut stage = ctx
            .staging
            .stage(&ctx.space)
            .await
            .map_err(|e| ComputeExecError::Internal(e.to_string()))?;
        stage
            .write_all(bytes)
            .await
            .map_err(|e| ComputeExecError::Internal(e.to_string()))?;
        inputs.insert((ctx.space.clone(), path.clone()), (Metadata(BTreeMap::new()), stage));
    }

    match ctx
        .tinycloud
        .invoke_with_options::<BlockStage>(invocation, inputs, KvInvokeOptions::default())
        .await
    {
        Ok((_, mut outcomes)) => match outcomes.pop() {
            Some(InvocationOutcome::KvRead(None)) => Ok(KvOutcome::ReadOk(None)),
            Some(InvocationOutcome::KvRead(Some((_, _, content)))) => {
                use futures::io::AsyncReadExt;
                let mut buf = Vec::new();
                let mut content = content;
                content
                    .read_to_end(&mut buf)
                    .await
                    .map_err(|e| ComputeExecError::Internal(e.to_string()))?;
                Ok(KvOutcome::ReadOk(Some(buf)))
            }
            Some(InvocationOutcome::KvWrite(_)) => Ok(KvOutcome::WriteOk),
            Some(InvocationOutcome::KvDelete(_)) => Ok(KvOutcome::DeleteOk),
            other => Err(ComputeExecError::Internal(format!(
                "unexpected KV invocation outcome for a compute host call: {other:?}"
            ))),
        },
        Err(err) => denial_or_internal(err, &resource_str, ability),
    }
}

async fn mediate_sql_call(
    ctx: &ExecutionCtx,
    ability: &'static str,
    request: SqlRequest,
) -> Result<SqlOutcome, ComputeExecError> {
    let resource_id = ctx.space.clone().to_resource(
        "sql".parse::<AuthService>().expect("\"sql\" is a valid service"),
        Some(
            COMPUTE_SQL_DB_NAME
                .parse::<AuthPath>()
                .expect("the compute sql db name is a valid path"),
        ),
        None,
        None,
    );
    let resource_str = resource_id.to_string();
    let invocation = mint_internal_invocation(ctx, &resource_id, ability)?;

    // Layer-a-style proof for the internal invocation: validate + persist it
    // with NO KV side effects (mirrors `verify_auth`), then separately run
    // the statement through `SqlService`, which installs the EXISTING
    // `create_authorizer` on the connection -- per-statement/table
    // restrictions still apply on top of this ability check.
    match ctx
        .tinycloud
        .invoke::<BlockStage>(invocation, std::collections::HashMap::new())
        .await
    {
        Ok(_) => {
            let result = ctx
                .sql_service
                .execute(
                    &ctx.space,
                    COMPUTE_SQL_DB_NAME,
                    request,
                    None,
                    ability.to_string(),
                )
                .await
                .map_err(|e| ComputeExecError::Internal(e.to_string()))?;
            Ok(SqlOutcome::Ok(result.response))
        }
        Err(err) => match denial_or_internal(err, &resource_str, ability)? {
            KvOutcome::Denied { ability, resource } => Ok(SqlOutcome::Denied { ability, resource }),
            _ => unreachable!("denial_or_internal only ever returns Denied on the Err arm"),
        },
    }
}

/// Translate a `TxStoreError` from an internal-invocation submission into
/// either the A.4 denial outcome (an authorization-layer rejection -- the
/// EXPECTED fail-closed path) or an `Err` (a genuine infrastructure
/// failure, which aborts the whole execution).
fn denial_or_internal(
    err: TxStoreError<BlockStores, BlockStage, tinycloud_core::keys::StaticSecret>,
    resource: &str,
    ability: &str,
) -> Result<KvOutcome, ComputeExecError> {
    match err {
        TxStoreError::Tx(TxError::InvalidInvocation(
            InvocationError::UnauthorizedAction(_, _)
            | InvocationError::MissingParents
            | InvocationError::CaveatsNotContained(_)
            | InvocationError::UnauthorizedInvoker(_),
        )) => Ok(KvOutcome::Denied {
            ability: ability.to_string(),
            resource: resource.to_string(),
        }),
        other => Err(ComputeExecError::Internal(other.to_string())),
    }
}

fn mint_internal_invocation(
    ctx: &ExecutionCtx,
    resource_id: &tinycloud_auth::resource::ResourceId,
    ability: &str,
) -> Result<Invocation, ComputeExecError> {
    let notabene = compute_function_binding_notabene(&ctx.content_cid);
    let mut caps = Capabilities::new();
    caps.with_action(
        resource_id.as_uri(),
        ability
            .parse::<UcanAbility>()
            .map_err(|e| ComputeExecError::Internal(format!("{e:?}")))?,
        [notabene],
    );

    let proof: Vec<AuthCid> = ctx.parents.iter().map(|h| h.to_cid(0x55)).collect();
    let nonce = format!("compute-call-{:032x}", rand::random::<u128>());

    let payload = Payload {
        issuer: ctx
            .routine_vm
            .parse::<DIDURLBuf>()
            .map_err(|e| ComputeExecError::Internal(format!("{e:?}")))?,
        audience: ctx
            .routine_did
            .parse::<DIDBuf>()
            .map_err(|e| ComputeExecError::Internal(format!("{e:?}")))?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)
            .map_err(|e| ComputeExecError::Internal(format!("{e:?}")))?,
        nonce: Some(nonce),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof,
        attenuation: caps,
    };
    let encoded = payload
        .sign(
            ctx.routine_jwk.get_algorithm().unwrap_or_default(),
            &ctx.routine_jwk,
        )
        .map_err(|e| ComputeExecError::Internal(format!("{e:?}")))?
        .encode()
        .map_err(|e| ComputeExecError::Internal(format!("{e:?}")))?;

    Invocation::from_header_ser::<TinyCloudInvocation>(&encoded)
        .map_err(|e| ComputeExecError::Internal(format!("{e:?}")))
}

/// Minimal JSON-schema-lite validator (compute-service.md §10.1 "inputs
/// (schema) ... JSON-schema check"). Supports `type`, `required`,
/// `properties`, `items`, and `enum` -- the practical subset used by the
/// P2 test matrix -- rather than pulling in a full external JSON-schema
/// crate for one caveat field.
pub fn validate_input_schema(schema: &serde_json::Value, input: &serde_json::Value) -> Result<(), String> {
    let Some(schema_obj) = schema.as_object() else {
        return Ok(());
    };
    if let Some(expected_type) = schema_obj.get("type").and_then(|v| v.as_str()) {
        if !json_type_matches(expected_type, input) {
            return Err(format!(
                "expected type \"{expected_type}\", got {}",
                json_type_name(input)
            ));
        }
    }
    if let Some(allowed) = schema_obj.get("enum").and_then(|v| v.as_array()) {
        if !allowed.contains(input) {
            return Err(format!("{input} is not one of the allowed enum values"));
        }
    }
    if let Some(obj) = input.as_object() {
        if let Some(required) = schema_obj.get("required").and_then(|v| v.as_array()) {
            for req in required {
                if let Some(name) = req.as_str() {
                    if !obj.contains_key(name) {
                        return Err(format!("missing required property \"{name}\""));
                    }
                }
            }
        }
        if let Some(properties) = schema_obj.get("properties").and_then(|v| v.as_object()) {
            for (name, subschema) in properties {
                if let Some(value) = obj.get(name) {
                    validate_input_schema(subschema, value)?;
                }
            }
        }
    }
    if let Some(arr) = input.as_array() {
        if let Some(item_schema) = schema_obj.get("items") {
            for item in arr {
                validate_input_schema(item_schema, item)?;
            }
        }
    }
    Ok(())
}

fn json_type_matches(expected: &str, value: &serde_json::Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_validator_enforces_required_and_type() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["x"],
            "properties": {"x": {"type": "string"}}
        });
        assert!(validate_input_schema(&schema, &serde_json::json!({"x": "hi"})).is_ok());
        assert!(validate_input_schema(&schema, &serde_json::json!({})).is_err());
        assert!(validate_input_schema(&schema, &serde_json::json!({"x": 1})).is_err());
    }
}

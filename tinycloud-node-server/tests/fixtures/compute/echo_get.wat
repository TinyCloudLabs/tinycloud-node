;; Cross-space isolation fixture (compute_execute.rs
;; `cross_space_isolation_same_bytes_two_spaces`, the F3 confused-deputy
;; regression, both judges' single most-wanted missing test). Calls
;; storage_get once and returns the host's raw JSON response VERBATIM as the
;; run() result -- unlike probe_get.wat (which returns a hardcoded literal),
;; this fixture lets the Rust test observe EXACTLY what value (if any) the
;; host actually read, so a cross-space data leak would be directly visible
;; in the execution result, not just inferable from the manifest.
(module
  (import "tinycloud" "storage_get" (func $get (param i32 i32) (result i32 i32)))
  (memory (export "memory") 1)
  (global $hp (mut i32) (i32.const 4096))
  (func (export "alloc") (param $l i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $hp))
    (global.set $hp (i32.add (global.get $hp) (local.get $l)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32 i32)
    (call $get (i32.const 0) (i32.const 14)))
  (data (i32.const 0) "{\"key\":\"in/x\"}"))

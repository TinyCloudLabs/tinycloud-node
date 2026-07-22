;; Memory-safety fixture (Codex P2 finding, compute_execute.rs
;; `bogus_host_call_length_rejected_cleanly`): the guest claims a
;; storage_get request length of ~2GB even though its own declared memory is
;; a single 64KiB page. The host MUST reject this against the configured
;; ABI message-size ceiling BEFORE allocating a host-side buffer sized by
;; the untrusted length -- not attempt a multi-gigabyte allocation.
(module
  (import "tinycloud" "storage_get" (func $get (param i32 i32) (result i32 i32)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "run") (param i32 i32) (result i32 i32)
    ;; Claim a ~2GB request length -- far past the node's default 8MiB ABI
    ;; message ceiling AND past the guest's own one-page memory.
    (call $get (i32.const 0) (i32.const 2000000000))
    (drop) (drop)
    (i32.const 0) (i32.const 0)))

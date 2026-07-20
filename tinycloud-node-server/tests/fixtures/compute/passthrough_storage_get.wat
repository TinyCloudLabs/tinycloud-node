;; Minimal single-import guest (compute_execute per-import matrix). `run`
;; forwards its input bytes VERBATIM as the host-call argument and returns the
;; host's response unchanged, so the test drives the key/value/sql via the
;; execute `input` and inspects the raw envelope (ok:true / A.4 denial).
(module
  (import "tinycloud" "storage_get" (func $call (param i32 i32) (result i32 i32)))
  (memory (export "memory") 2)
  (global $hp (mut i32) (i32.const 0x1000))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $hp))
    (global.set $hp (i32.add (global.get $hp) (local.get $len)))
    (local.get $p))
  (func (export "run") (param $ptr i32) (param $len i32) (result i32 i32)
    (call $call (local.get $ptr) (local.get $len))))

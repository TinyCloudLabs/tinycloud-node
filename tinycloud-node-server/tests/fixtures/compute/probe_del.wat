;; Single-import probe (P2 enforcement matrix, compute_execute): calls one
;; host import once with a fixed request and returns a fixed valid result
;; `{"ok":true}`, so the guest result NEVER depends on the host response --
;; a denial (envelope into guest memory) still yields a parseable result and
;; the test asserts the manifest `granted` flag for the single call.
(module
  (import "tinycloud" "storage_del" (func $op (param i32 i32) (result i32 i32)))
  (memory (export "memory") 1)
  (global $hp (mut i32) (i32.const 4096))
  (func (export "alloc") (param $l i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $hp))
    (global.set $hp (i32.add (global.get $hp) (local.get $l)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32 i32)
    (call $op (i32.const 0) (i32.const 15))
    (drop) (drop)
    (i32.const 128) (i32.const 11))
  (data (i32.const 0) "{\"key\":\"out/y\"}")
  (data (i32.const 128) "{\"ok\":true}"))

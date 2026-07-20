;; Non-terminating guest (compute_execute: fuel exhaustion + epoch timeout).
;; `run` loops forever doing cheap work, so it traps on EITHER fuel exhaustion
;; (Store::set_fuel) OR the epoch deadline (epoch interruption), whichever the
;; test configures the caveat to trip first (compute-service.md §10.1).
(module
  (memory (export "memory") 1)
  (global $hp (mut i32) (i32.const 0x1000))
  (global $acc (mut i32) (i32.const 0))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $hp))
    (global.set $hp (i32.add (global.get $hp) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32 i32)
    (loop $spin
      (global.set $acc (i32.add (global.get $acc) (i32.const 1)))
      (br $spin))
    ;; unreachable
    (i32.const 0) (i32.const 0)))

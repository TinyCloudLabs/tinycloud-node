;; Memory-growth guest (compute_execute: maxMemory / StoreLimits). `run`
;; repeatedly `memory.grow`s by one page until the wasmtime `StoreLimits`
;; memory ceiling denies growth (grow returns -1); the guest then dereferences
;; past the current bound, trapping deterministically. With a small `maxMemory`
;; caveat this fails; with a large ceiling it would succeed (the test asserts
;; the failure under a tight ceiling, compute-service.md §10.1).
(module
  (memory (export "memory") 1)
  (global $hp (mut i32) (i32.const 0x1000))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $hp))
    (global.set $hp (i32.add (global.get $hp) (local.get $len)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32 i32)
    (local $i i32)
    (local.set $i (i32.const 0))
    (block $done
      (loop $grow
        ;; grow by 16 pages (1 MiB) at a time; -1 means the limiter denied it.
        (if (i32.eq (memory.grow (i32.const 16)) (i32.const -1))
          (then (br $done)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        ;; hard cap the loop count so a mis-set (too-large) ceiling still
        ;; terminates instead of running for the full fuel budget.
        (br_if $grow (i32.lt_u (local.get $i) (i32.const 100000)))))
    ;; touch one byte past the (denied) growth to force a trap even when the
    ;; limiter merely refused growth without trapping.
    (i32.store (i32.mul (memory.size) (i32.const 65536)) (i32.const 1))
    (i32.const 0) (i32.const 0)))

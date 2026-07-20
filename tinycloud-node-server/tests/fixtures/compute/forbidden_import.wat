;; compute-service.md §10.1 "forbidden import" / A.4 note (the DISTINCT,
;; separately-tested case): a guest that imports a function OUTSIDE the
;; four-function "tinycloud" host surface must fail at module INSTANTIATION
;; (a deterministic wasmtime LINK error), NOT at run time and NOT as an
;; ability-denial envelope.
;;
;; Here the guest imports `env.exfiltrate` -- a module/name the host linker
;; never defines -- so `Linker::instantiate` fails to resolve the import.
;; The compute backend registers ONLY module "tinycloud"'s four imports, so
;; there is no `env` module at all.

(module
  ;; legitimate imports (present) ...
  (import "tinycloud" "storage_get" (func $storage_get (param i32 i32) (result i32 i32)))
  ;; ... plus one forbidden import the host will NOT satisfy:
  (import "env" "exfiltrate" (func $exfiltrate (param i32 i32) (result i32)))

  (memory (export "memory") 1)
  (global $hp (mut i32) (i32.const 0x1000))

  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $hp))
    (global.set $hp (i32.add (global.get $hp) (local.get $len)))
    (local.get $p))

  (func (export "run") (param i32 i32) (result i32 i32)
    ;; never reached -- instantiation fails first.
    (i32.const 0) (i32.const 0)))

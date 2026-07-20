;; §10.1 "forbidden import" fixture (compute-service.md Appendix A.4 note):
;; a guest that imports a function OUTSIDE the four-function "tinycloud"
;; host surface must fail at module INSTANTIATION (a deterministic link
;; error), distinct from the A.4 ability-denial contract. The host's
;; `wasmtime::Linker` only ever registers the four pinned imports, so any
;; other import name fails to resolve automatically -- this fixture just
;; needs to declare one.
(module
  (import "tinycloud" "storage_get" (func $get (param i32 i32) (result i32 i32)))
  (import "tinycloud" "network_fetch" (func $fetch (param i32 i32) (result i32 i32)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "run") (param i32 i32) (result i32 i32) (i32.const 0) (i32.const 0)))

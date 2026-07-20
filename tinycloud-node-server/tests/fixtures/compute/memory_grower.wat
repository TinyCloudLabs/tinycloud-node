;; §10.1 `maxMemory` -> wasmtime `StoreLimits` enforcement fixture: `run`
;; asks to grow linear memory by 1000 pages (~65MB). Under a low configured
;; memory cap, `memory.grow` fails (returns -1) WITHOUT trapping the guest
;; (standard wasm semantics) -- the test observes this from the HOST side by
;; checking the store's memory size is unchanged after `run` returns, not by
;; having the guest report the grow result.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "run") (param i32 i32) (result i32 i32)
    (drop (memory.grow (i32.const 1000)))
    (i32.const 0)
    (i32.const 0)))

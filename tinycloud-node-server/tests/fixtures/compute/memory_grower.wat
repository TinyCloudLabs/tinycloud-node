;; §10.1 `maxMemory` -> wasmtime `StoreLimits` enforcement fixture. `run`
;; asks to grow linear memory by 1000 pages (~64 MB). Under a low configured
;; memory cap the limiter denies the grow: `memory.grow` returns -1 WITHOUT
;; trapping the guest (standard wasm semantics). The guest reports the
;; outcome as a valid JSON result so the HOST-side test can assert it:
;;   grow denied (capped) -> {"grew":false}
;;   grow allowed         -> {"grew":true}
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 4096))
  (func (export "run") (param i32 i32) (result i32 i32)
    (if (result i32 i32) (i32.eq (memory.grow (i32.const 1000)) (i32.const -1))
      (then (i32.const 0) (i32.const 14))     ;; {"grew":false}
      (else (i32.const 16) (i32.const 13))))  ;; {"grew":true}
  (data (i32.const 0) "{\"grew\":false}")
  (data (i32.const 16) "{\"grew\":true}"))

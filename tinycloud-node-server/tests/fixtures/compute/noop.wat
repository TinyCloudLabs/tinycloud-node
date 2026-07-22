;; A trivial, valid module -- pinned ABI, no host calls, empty result.
;; Used by tests that assert enforcement happening BEFORE the guest ever
;; runs (allowlist, input-schema, numeric-ceiling, rotation-tripwire), so
;; the guest body itself is irrelevant.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "run") (param i32 i32) (result i32 i32) (i32.const 0) (i32.const 0)))

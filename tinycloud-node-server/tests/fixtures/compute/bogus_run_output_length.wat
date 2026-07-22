;; Memory-safety fixture (Codex P2 finding, compute_execute.rs
;; `bogus_run_output_length_rejected_cleanly`): `run()` returns a NEGATIVE
;; result length. Cast naively to `usize` this wraps to an enormous value.
;; The host MUST reject this cleanly (a bounded, defined error) before
;; casting the guest-controlled length into a host allocation size.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "run") (param i32 i32) (result i32 i32)
    (i32.const 0) (i32.const -1)))

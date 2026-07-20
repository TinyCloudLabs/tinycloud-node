;; §10.1 fuel-exhaustion and epoch/timeout enforcement fixture: an
;; unconditional infinite loop with no host calls, so it burns fuel and
;; epoch ticks deterministically without depending on wall-clock timing for
;; ITS OWN behavior (the test picks a small fuel budget, or a short epoch
;; deadline, and asserts the run traps rather than hanging).
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "run") (param i32 i32) (result i32 i32)
    (loop $l (br $l))
    (i32.const 0)
    (i32.const 0)))

;; D-SQL fixture (compute_execute.rs
;; `constrained_statements_sql_caveat_enforced_on_compute_path`): the routine
;; calls sql_query with a NAMED prepared statement ("allowed") that the
;; D_fn's constrained-statements caveat permits. Returns the host's raw
;; sql_query response VERBATIM so the Rust test observes the actual query
;; result, proving the allowed statement ran.
(module
  (import "tinycloud" "sql_query" (func $sql (param i32 i32) (result i32 i32)))
  (memory (export "memory") 1)
  (global $hp (mut i32) (i32.const 4096))
  (func (export "alloc") (param $l i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $hp))
    (global.set $hp (i32.add (global.get $hp) (local.get $l)))
    (local.get $p))
  (func (export "run") (param i32 i32) (result i32 i32)
    (call $sql (i32.const 0) (i32.const 58)))
  ;; {"action":"executeStatement","name":"allowed","params":[]}  (58 bytes)
  (data (i32.const 0) "{\"action\":\"executeStatement\",\"name\":\"allowed\",\"params\":[]}"))

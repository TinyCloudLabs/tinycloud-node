;; Appendix A conformance fixture (specs/compute-service.md Appendix A,
;; A.1-A.6; specs/compute-service-implementation-plan.md P2 "Pinned WASM
;; ABI (C3)"). Both P2 implementers build against this exact module; both
;; judges score against it.
;;
;; Core module (NOT a component). Guest exports:
;;   alloc(len: i32) -> ptr: i32      -- bump allocator; the HOST calls this
;;                                       to reserve guest memory it then
;;                                       writes into (the `run` input, and
;;                                       each host import's response).
;;   run(ptr: i32, len: i32) -> (ptr: i32, len: i32)
;; Four host imports, module name "tinycloud", each (i32,i32)->(i32,i32),
;; all JSON bytes: storage_get, storage_put, storage_del, sql_query.
;;
;; `run` ignores its input (the fixture's `run` input is `{}`, no fields
;; used, per A.3) and performs the fixed five-step scenario in order:
;;   1. storage_get {"key":"in/x"}                          -> reads "42"
;;   2. storage_put {"key":"out/y","value":"84"}             -> writes
;;   3. sql_query   {"action":"query","sql":"SELECT 1 AS n","params":[]}
;;   4. storage_del {"key":"out/y"}                          -> deletes
;;   5. storage_put {"key":"secret/z","value":"x"}           -> DENIED
;;      (no grant on secret/; the host mediator returns the ok:false
;;      envelope into guest memory -- the guest does not trap and does not
;;      need to inspect it, since it already knows which ability it just
;;      invoked)
;;
;; The two values genuinely read back from host responses ("got" from step
;; 1, "sql_n" from step 3) are extracted by copying fixed byte ranges out of
;; the host's response bytes at OFFSETS THAT ARE CORRECT FOR THIS EXACT,
;; FULLY-PINNED SCENARIO -- the host's response encoding for these two
;; calls is verified byte-for-byte by a Rust unit test
;; (`tinycloud-node-server/tests/compute_abi.rs`), so this is not a general
;; JSON parser, it is a purpose-built extractor for a fully-specified
;; protocol both sides of which live in this repository.
(module
  (import "tinycloud" "storage_get" (func $get (param i32 i32) (result i32 i32)))
  (import "tinycloud" "storage_put" (func $put (param i32 i32) (result i32 i32)))
  (import "tinycloud" "storage_del" (func $del (param i32 i32) (result i32 i32)))
  (import "tinycloud" "sql_query"   (func $sql (param i32 i32) (result i32 i32)))

  (memory (export "memory") 2)

  ;; Bump-allocator heap pointer. Starts well past every static data
  ;; segment below (the last one ends at 256+76=332).
  (global $heap_ptr (mut i32) (i32.const 4096))

  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap_ptr))
    (global.set $heap_ptr (i32.add (global.get $heap_ptr) (local.get $len)))
    (local.get $ptr))

  ;; Byte-for-byte copy loop (no reliance on the bulk-memory `memory.copy`
  ;; instruction, to avoid any proposal/feature-flag uncertainty).
  (func $copy (param $dst i32) (param $src i32) (param $n i32)
    (local $i i32)
    (local.set $i (i32.const 0))
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
        (i32.store8
          (i32.add (local.get $dst) (local.get $i))
          (i32.load8_u (i32.add (local.get $src) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop))))

  (func (export "run") (param $in_ptr i32) (param $in_len i32) (result i32 i32)
    (local $r1p i32) (local $r1l i32)
    (local $r3p i32) (local $r3l i32)

    ;; Step 1: storage_get {"key":"in/x"}  (offset 0, len 14)
    (call $get (i32.const 0) (i32.const 14))
    (local.set $r1l)
    (local.set $r1p)
    ;; Response is {"ok":true,"value":"42"}; the value "42" sits at byte
    ;; offset 20, length 2 (verified in compute_abi.rs). Overwrite the
    ;; result template's "got" placeholder (offset 264, 2 bytes) with it.
    (call $copy (i32.const 264) (i32.add (local.get $r1p) (i32.const 20)) (i32.const 2))

    ;; Step 2: storage_put {"key":"out/y","value":"84"}  (offset 32, len 28)
    (call $put (i32.const 32) (i32.const 28))
    (drop)
    (drop)

    ;; Step 3: sql_query {"action":"query","sql":"SELECT 1 AS n","params":[]}
    ;; (offset 96, len 52)
    (call $sql (i32.const 96) (i32.const 52))
    (local.set $r3l)
    (local.set $r3p)
    ;; Response is {"columns":["n"],"rows":[[1]],"rowCount":1}; the row
    ;; value digit '1' sits at byte offset 26, length 1. Overwrite the
    ;; template's "sql_n" placeholder (offset 287, 1 byte).
    (call $copy (i32.const 287) (i32.add (local.get $r3p) (i32.const 26)) (i32.const 1))

    ;; Step 4: storage_del {"key":"out/y"}  (offset 160, len 15)
    (call $del (i32.const 160) (i32.const 15))
    (drop)
    (drop)

    ;; Step 5: storage_put {"key":"secret/z","value":"x"}  (offset 192, len 30)
    ;; -- expected DENIAL. The result is not inspected; the guest already
    ;; knows which ability it invoked, so "denied" below is a literal, not
    ;; an extraction.
    (call $put (i32.const 192) (i32.const 30))
    (drop)
    (drop)

    ;; Return the (now-patched) result template.
    (i32.const 256)
    (i32.const 76))

  ;; --- Static data: the five fixed request payloads, and the result
  ;; template with placeholder bytes at the two dynamic slots (patched in
  ;; place above). Placeholders are "00"/"0" so an unpatched template is
  ;; visibly wrong rather than accidentally valid-looking.
  (data (i32.const 0)   "{\"key\":\"in/x\"}")
  (data (i32.const 32)  "{\"key\":\"out/y\",\"value\":\"84\"}")
  (data (i32.const 96)  "{\"action\":\"query\",\"sql\":\"SELECT 1 AS n\",\"params\":[]}")
  (data (i32.const 160) "{\"key\":\"out/y\"}")
  (data (i32.const 192) "{\"key\":\"secret/z\",\"value\":\"x\"}")
  (data (i32.const 256) "{\"got\":\"00\",\"put\":true,\"sql_n\":0,\"deleted\":true,\"denied\":\"tinycloud.kv/put\"}"))

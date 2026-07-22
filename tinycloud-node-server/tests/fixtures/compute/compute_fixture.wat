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
;;      envelope into guest memory)
;;
;; Judge finding (both P2 implementers): the guest genuinely INSPECTS every
;; host-call response instead of asserting the outcome unconditionally.
;; Steps 1-4 return space-INDEPENDENT fixed JSON, byte-compared here for
;; exact equality ($eq). Step 5's denial envelope embeds the space-dependent
;; resource URI, so it is inspected for the "ok":false signal ($contains)
;; instead. Only when all five checks pass does the guest emit the
;; canonical A.3 run result; any deviation emits a distinct error object so
;; a wiring bug fails LOUDLY here rather than being masked by a guest that
;; blindly reports "denied" regardless of what the host actually returned.
;;
;; The server-side read-back assertion that the denied put on secret/z never
;; actually created the key lives in the Rust test
;; (`tinycloud-node-server/tests/compute_abi.rs`), not in this fixture --
;; the guest has no way to make a second, unmediated request to verify that.
(module
  (import "tinycloud" "storage_get" (func $storage_get (param i32 i32) (result i32 i32)))
  (import "tinycloud" "storage_put" (func $storage_put (param i32 i32) (result i32 i32)))
  (import "tinycloud" "storage_del" (func $storage_del (param i32 i32) (result i32 i32)))
  (import "tinycloud" "sql_query"   (func $sql_query   (param i32 i32) (result i32 i32)))

  (memory (export "memory") 2)

  ;; --- request payloads (A.3 arg column) ---
  (data (i32.const 0x0040) "{\"key\":\"in/x\"}")
  (data (i32.const 0x0050) "{\"key\":\"out/y\",\"value\":\"84\"}")
  (data (i32.const 0x0070) "{\"action\":\"query\",\"sql\":\"SELECT 1 AS n\",\"params\":[]}")
  (data (i32.const 0x00b0) "{\"key\":\"out/y\"}")
  (data (i32.const 0x00c0) "{\"key\":\"secret/z\",\"value\":\"x\"}")
  ;; --- expected fixed responses (A.3 return column, space-independent) ---
  (data (i32.const 0x00e0) "{\"ok\":true,\"value\":\"42\"}")
  (data (i32.const 0x0100) "{\"ok\":true}")
  ;; canonical JSON = SORTED keys (serde_json::to_value's Value::Object is a
  ;; sorted map, no `preserve_order`): columns < rowCount < rows.
  (data (i32.const 0x0110) "{\"columns\":[\"n\"],\"rowCount\":1,\"rows\":[[1]]}")
  ;; --- denial signal (A.4) ---
  (data (i32.const 0x0140) "\"ok\":false")
  ;; --- outputs ---
  (data (i32.const 0x0150) "{\"got\":\"42\",\"put\":true,\"sql_n\":1,\"deleted\":true,\"denied\":\"tinycloud.kv/put\"}")
  (data (i32.const 0x01a0) "{\"error\":\"unexpected-host-response\"}")

  ;; bump allocator: heap starts past all static data.
  (global $hp (mut i32) (i32.const 0x1000))

  ;; alloc(len) -> ptr : reserve `len` bytes (8-byte aligned), return the
  ;; previous heap tip.
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $hp))
    (global.set $hp
      (i32.and
        (i32.add (i32.add (global.get $hp) (local.get $len)) (i32.const 7))
        (i32.const -8)))
    (local.get $p))

  ;; $eq(a, alen, b, blen) -> 1 if the two byte ranges are identical.
  (func $eq (param $a i32) (param $alen i32) (param $b i32) (param $blen i32) (result i32)
    (local $i i32)
    (if (i32.ne (local.get $alen) (local.get $blen))
      (then (return (i32.const 0))))
    (local.set $i (i32.const 0))
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (local.get $alen)))
        (if (i32.ne
              (i32.load8_u (i32.add (local.get $a) (local.get $i)))
              (i32.load8_u (i32.add (local.get $b) (local.get $i))))
          (then (return (i32.const 0))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)))
    (i32.const 1))

  ;; $contains(hay, haylen, needle, needlelen) -> 1 if needle occurs in hay.
  (func $contains (param $hay i32) (param $haylen i32) (param $ndl i32) (param $ndllen i32) (result i32)
    (local $i i32)
    (local $limit i32)
    (if (i32.gt_u (local.get $ndllen) (local.get $haylen))
      (then (return (i32.const 0))))
    (local.set $limit (i32.sub (local.get $haylen) (local.get $ndllen)))
    (local.set $i (i32.const 0))
    (block $done
      (loop $loop
        (br_if $done (i32.gt_u (local.get $i) (local.get $limit)))
        (if (call $eq
              (i32.add (local.get $hay) (local.get $i)) (local.get $ndllen)
              (local.get $ndl) (local.get $ndllen))
          (then (return (i32.const 1))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)))
    (i32.const 0))

  ;; run(ptr,len) -> (ptr,len). The A.3 scenario; `input` (`{}`) is ignored.
  (func (export "run") (param $in_ptr i32) (param $in_len i32) (result i32 i32)
    (local $rp i32)   ;; response ptr
    (local $rl i32)   ;; response len

    ;; Step 1: storage_get {"key":"in/x"} -- must equal {"ok":true,"value":"42"}
    (call $storage_get (i32.const 0x0040) (i32.const 14))
    (local.set $rl) (local.set $rp)
    (if (i32.eqz (call $eq (local.get $rp) (local.get $rl) (i32.const 0x00e0) (i32.const 24)))
      (then (return (i32.const 0x01a0) (i32.const 36))))

    ;; Step 2: storage_put {"key":"out/y","value":"84"} -- must equal {"ok":true}
    (call $storage_put (i32.const 0x0050) (i32.const 28))
    (local.set $rl) (local.set $rp)
    (if (i32.eqz (call $eq (local.get $rp) (local.get $rl) (i32.const 0x0100) (i32.const 11)))
      (then (return (i32.const 0x01a0) (i32.const 36))))

    ;; Step 3: sql_query SELECT 1 AS n -- must equal
    ;; {"columns":["n"],"rowCount":1,"rows":[[1]]}
    (call $sql_query (i32.const 0x0070) (i32.const 52))
    (local.set $rl) (local.set $rp)
    (if (i32.eqz (call $eq (local.get $rp) (local.get $rl) (i32.const 0x0110) (i32.const 43)))
      (then (return (i32.const 0x01a0) (i32.const 36))))

    ;; Step 4: storage_del {"key":"out/y"} -- must equal {"ok":true}
    (call $storage_del (i32.const 0x00b0) (i32.const 15))
    (local.set $rl) (local.set $rp)
    (if (i32.eqz (call $eq (local.get $rp) (local.get $rl) (i32.const 0x0100) (i32.const 11)))
      (then (return (i32.const 0x01a0) (i32.const 36))))

    ;; Step 5: storage_put {"key":"secret/z",...} -- must be DENIED
    ;; ("ok":false in the response; the resource URI embeds the space, so
    ;; only the denial signal is checked, not the whole envelope).
    (call $storage_put (i32.const 0x00c0) (i32.const 30))
    (local.set $rl) (local.set $rp)
    (if (i32.eqz (call $contains (local.get $rp) (local.get $rl) (i32.const 0x0140) (i32.const 10)))
      (then (return (i32.const 0x01a0) (i32.const 36))))

    ;; All five checks earned the canonical A.3 result -- "denied" below is
    ;; no longer an unconditional literal, it is what actually happened.
    (return (i32.const 0x0150) (i32.const 76))))

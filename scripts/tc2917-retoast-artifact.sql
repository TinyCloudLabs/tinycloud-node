-- Operator only, after the TC-2917 migration. One explicitly selected row/transaction.
-- psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -v service=sql -v space=... -v name=... \
--   -f scripts/tc2917-retoast-artifact.sql
-- No payloads or identities are printed. Re-run for each reviewed large row.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '500ms';
SET LOCAL statement_timeout = '120s';
CREATE TEMP TABLE tc2917_before ON COMMIT DROP AS
SELECT service, space, name, revision, content_hash, checkpoint_content_hash,
       delta_content_hash, octet_length(payload) AS payload_length,
       octet_length(delta_payload) AS delta_length,
       sha256(payload) AS payload_digest, sha256(delta_payload) AS delta_digest
FROM database_artifact
WHERE service = :'service' AND space = :'space' AND name = :'name'
  AND (octet_length(payload) > 8388608 OR octet_length(delta_payload) > 8388608);
DO $$ BEGIN
    IF (SELECT count(*) FROM tc2917_before) <> 1 THEN
        RAISE EXCEPTION 'expected one explicitly selected large artifact';
    END IF;
    IF (SELECT count(*) FROM pg_attribute
        WHERE attrelid = 'database_artifact'::regclass
          AND attname IN ('payload', 'delta_payload') AND attstorage = 'e') <> 2 THEN
        RAISE EXCEPTION 'EXTERNAL migration must be applied first';
    END IF;
END $$;
-- Concatenation constructs a new datum; plain assignment can reuse old TOAST.
-- Both parts are re-toasted so a compressed smaller WAL cannot survive the rewrite.
UPDATE database_artifact a
SET payload = a.payload || ''::bytea,
    delta_payload = a.delta_payload || ''::bytea
FROM tc2917_before b
WHERE (a.service, a.space, a.name) = (b.service, b.space, b.name)
  AND a.revision = b.revision
  AND a.checkpoint_content_hash = b.checkpoint_content_hash
  AND a.content_hash = b.content_hash
  AND a.delta_content_hash IS NOT DISTINCT FROM b.delta_content_hash;
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM database_artifact a JOIN tc2917_before b
        USING (service, space, name)
        WHERE a.revision = b.revision AND a.content_hash = b.content_hash
          AND a.checkpoint_content_hash = b.checkpoint_content_hash
          AND a.delta_content_hash IS NOT DISTINCT FROM b.delta_content_hash
          AND octet_length(a.payload) = b.payload_length
          AND octet_length(a.delta_payload) IS NOT DISTINCT FROM b.delta_length
          AND sha256(a.payload) = b.payload_digest
          AND sha256(a.delta_payload) IS NOT DISTINCT FROM b.delta_digest
          AND pg_column_compression(a.payload) IS NULL
          AND pg_column_compression(a.delta_payload) IS NULL
    ) THEN
        RAISE EXCEPTION 'artifact changed or re-toast/integrity verification failed';
    END IF;
END $$;
COMMIT;

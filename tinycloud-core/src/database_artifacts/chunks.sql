CREATE TABLE artifact_storage_settings (
    id integer PRIMARY KEY CHECK(id=1), account_limit bigint NOT NULL DEFAULT 0,
    artifact_limit bigint NOT NULL DEFAULT 0
);
INSERT INTO artifact_storage_settings(id) VALUES(1);
CREATE TABLE artifact_account (
    owner text PRIMARY KEY,
    legacy_bytes bigint NOT NULL DEFAULT 0 CHECK(legacy_bytes>=0),
    reserved_bytes bigint NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0),
    credit_bytes bigint NOT NULL DEFAULT 0 CHECK(credit_bytes>=0)
);
CREATE TABLE artifact_space_owner (
    space text PRIMARY KEY, owner text NOT NULL REFERENCES artifact_account(owner)
);
CREATE INDEX artifact_space_owner_owner ON artifact_space_owner(owner);
-- Space names cannot contain colons. Remove exactly the final name component,
-- never a DID prefix (did:web owners may themselves have colon components).
CREATE FUNCTION artifact_owner(space text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN space LIKE 'tinycloud:%'
 THEN 'did:' || regexp_replace(substr(space,11), ':[^:]+$', '')
 ELSE 'legacy:' || space END
$$;
CREATE TABLE artifact_part (
    service text NOT NULL, space text NOT NULL, name text NOT NULL,
    part_id text NOT NULL, owner text NOT NULL REFERENCES artifact_account(owner),
    size_bytes bigint NOT NULL CHECK(size_bytes>=0), content_hash text,
    chunk_count integer NOT NULL CHECK(chunk_count>=0),
    replacement_credit bigint NOT NULL DEFAULT 0 CHECK(replacement_credit>=0),
    replacing boolean NOT NULL DEFAULT false, replaces_part_id text,
    state text NOT NULL DEFAULT 'uploading'  CHECK(state IN ('uploading','sealed','published','deleting')),
    lease_until timestamptz NOT NULL DEFAULT clock_timestamp()+interval '120 seconds',
    PRIMARY KEY(service,space,name,part_id),
    FOREIGN KEY(service,space,name,replaces_part_id) REFERENCES artifact_part(service,space,name,part_id)
);
CREATE UNIQUE INDEX artifact_part_replacement ON artifact_part(service,space,name) WHERE replacing;
CREATE INDEX artifact_part_reap ON artifact_part(lease_until) WHERE state<>'published';
CREATE INDEX artifact_part_reap_owner ON artifact_part(owner,lease_until) WHERE state<>'published';
CREATE TABLE artifact_chunk (
    service text NOT NULL, space text NOT NULL, name text NOT NULL,
    part_id text NOT NULL, ordinal integer NOT NULL CHECK(ordinal>=0),
    payload bytea NOT NULL CHECK(octet_length(payload) BETWEEN 1 AND 1048576),
    PRIMARY KEY(service,space,name,part_id,ordinal),
    FOREIGN KEY(service,space,name,part_id) REFERENCES artifact_part(service,space,name,part_id)
);
ALTER TABLE artifact_chunk ALTER COLUMN payload SET STORAGE EXTERNAL;
ALTER TABLE database_artifact ADD COLUMN checkpoint_part_id text;
ALTER TABLE database_artifact ADD COLUMN delta_part_id text;
ALTER TABLE database_artifact ADD COLUMN layout_generation bigint NOT NULL DEFAULT 0;
ALTER TABLE database_artifact ADD CONSTRAINT artifact_checkpoint_part_fk
 FOREIGN KEY(service,space,name,checkpoint_part_id) REFERENCES artifact_part(service,space,name,part_id);
ALTER TABLE database_artifact ADD CONSTRAINT artifact_delta_part_fk
 FOREIGN KEY(service,space,name,delta_part_id) REFERENCES artifact_part(service,space,name,part_id);

CREATE FUNCTION artifact_chunk_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s text;
BEGIN
 IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'artifact chunks are immutable'; END IF;
 IF TG_OP='DELETE' THEN
   SELECT state INTO s FROM artifact_part WHERE service=OLD.service AND space=OLD.space
     AND name=OLD.name AND part_id=OLD.part_id FOR SHARE;
   IF s IS DISTINCT FROM 'deleting' THEN RAISE EXCEPTION 'artifact part is not deleting'; END IF;
   RETURN OLD;
 END IF;
 SELECT state INTO s FROM artifact_part WHERE service=NEW.service AND space=NEW.space
   AND name=NEW.name AND part_id=NEW.part_id FOR SHARE;
 IF s IS DISTINCT FROM 'uploading' THEN RAISE EXCEPTION 'artifact part is not uploading'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER artifact_chunk_guard BEFORE INSERT OR UPDATE OR DELETE ON artifact_chunk
 FOR EACH ROW EXECUTE FUNCTION artifact_chunk_guard();

-- Activation is separate from migration. With the switch off, no owner
-- inventory is scanned or maintained. A short writer fence makes the initial
-- exact-owner inventory and quota activation atomic with old-binary writes.
CREATE FUNCTION artifact_enable(limit_bytes bigint, part_limit bigint) RETURNS void LANGUAGE plpgsql AS $$
DECLARE previous bigint; previous_timeout text:=current_setting('lock_timeout');
BEGIN
 SELECT account_limit INTO previous FROM artifact_storage_settings WHERE id=1;
 IF previous=limit_bytes AND (SELECT artifact_limit FROM artifact_storage_settings WHERE id=1)=part_limit THEN RETURN; END IF;
 SELECT account_limit INTO previous FROM artifact_storage_settings WHERE id=1 FOR UPDATE;
 IF previous=limit_bytes AND (SELECT artifact_limit FROM artifact_storage_settings WHERE id=1)=part_limit THEN RETURN; END IF;
 IF limit_bytes<=0 OR part_limit<=0 THEN RAISE EXCEPTION 'explicit artifact quota required'; END IF;
 IF previous=0 THEN
   PERFORM set_config('lock_timeout','500ms',true);
   LOCK TABLE database_artifact IN SHARE ROW EXCLUSIVE MODE;
   ALTER TABLE database_artifact ENABLE TRIGGER artifact_metadata_guard;
   ALTER TABLE database_artifact ENABLE TRIGGER artifact_metadata_retire;
   INSERT INTO artifact_account(owner,legacy_bytes)
    SELECT artifact_owner(space), COALESCE(sum(size_bytes),0)
    FROM database_artifact WHERE checkpoint_part_id IS NULL GROUP BY artifact_owner(space)
    ON CONFLICT(owner) DO UPDATE SET legacy_bytes=EXCLUDED.legacy_bytes;
   INSERT INTO artifact_space_owner(space,owner)
    SELECT DISTINCT space,artifact_owner(space) FROM database_artifact ON CONFLICT DO NOTHING;
   PERFORM set_config('lock_timeout',previous_timeout,true);
 END IF;
 UPDATE artifact_storage_settings SET account_limit=limit_bytes,artifact_limit=part_limit WHERE id=1;
END $$;

CREATE FUNCTION artifact_layout_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND OLD.checkpoint_part_id IS NOT NULL THEN
   IF NEW.checkpoint_part_id IS NULL OR NEW.storage_mode<>'checkpoint-parts-v1'
      OR (NEW.checkpoint_part_id=OLD.checkpoint_part_id AND
          (NEW.revision,NEW.content_hash,NEW.payload,NEW.delta_payload,NEW.layout_generation)
          IS DISTINCT FROM
          (OLD.revision,OLD.content_hash,OLD.payload,OLD.delta_payload,OLD.layout_generation)) THEN
     RAISE EXCEPTION 'TC2917_LAYOUT: legacy writes cannot replace checkpoint parts';
   END IF;
 END IF;
 IF TG_OP<>'DELETE' AND NEW.checkpoint_part_id IS NOT NULL THEN
   IF NEW.storage_mode<>'checkpoint-parts-v1' OR NEW.delta_payload IS NOT NULL
      OR octet_length(NEW.payload)<>0 OR NEW.delta_part_id IS NOT NULL THEN
     RAISE EXCEPTION 'TC2917_LAYOUT: invalid checkpoint layout';
   END IF;
   IF TG_OP='INSERT' THEN
     IF NEW.layout_generation<>1 THEN RAISE EXCEPTION 'TC2917_LAYOUT: invalid generation'; END IF;
   ELSIF NEW.checkpoint_part_id IS DISTINCT FROM OLD.checkpoint_part_id
      AND NEW.layout_generation<>OLD.layout_generation+1 THEN
     RAISE EXCEPTION 'TC2917_LAYOUT: invalid generation';
   END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE TRIGGER artifact_layout_guard BEFORE INSERT OR UPDATE OR DELETE ON database_artifact
 FOR EACH ROW EXECUTE FUNCTION artifact_layout_guard();

CREATE FUNCTION artifact_metadata_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE who text; old_bytes bigint:=0; new_bytes bigint:=0; cap bigint;
BEGIN
 SELECT account_limit INTO cap FROM artifact_storage_settings WHERE id=1;
 IF cap=0 THEN
   IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
 END IF;
 IF TG_OP='DELETE' THEN who:=artifact_owner(OLD.space); ELSE who:=artifact_owner(NEW.space); END IF;
 IF TG_OP='UPDATE' AND (NEW.service,NEW.space,NEW.name) IS DISTINCT FROM (OLD.service,OLD.space,OLD.name) THEN
   RAISE EXCEPTION 'artifact identity is immutable';
 END IF;
 INSERT INTO artifact_account(owner) VALUES(who) ON CONFLICT DO NOTHING;
 IF TG_OP<>'DELETE' THEN
   INSERT INTO artifact_space_owner(space,owner) VALUES(NEW.space,who) ON CONFLICT DO NOTHING;
   IF NEW.checkpoint_part_id IS NULL THEN new_bytes:=NEW.size_bytes; END IF;
 END IF;
 IF TG_OP<>'INSERT' AND OLD.checkpoint_part_id IS NULL THEN old_bytes:=OLD.size_bytes; END IF;
 UPDATE artifact_account SET legacy_bytes=legacy_bytes+new_bytes-old_bytes
 WHERE owner=who AND (new_bytes<=old_bytes OR legacy_bytes+reserved_bytes-credit_bytes+new_bytes-old_bytes<=cap);
 IF NOT FOUND THEN RAISE EXCEPTION 'TC2917_QUOTA'; END IF;
 IF TG_OP='UPDATE' AND NEW.checkpoint_part_id IS NULL AND EXISTS(
   SELECT 1 FROM artifact_part WHERE service=NEW.service AND space=NEW.space AND name=NEW.name AND replacing
 ) THEN RAISE EXCEPTION 'TC2917_LAYOUT: replacement in progress'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE TRIGGER artifact_metadata_guard BEFORE INSERT OR UPDATE OR DELETE ON database_artifact
 FOR EACH ROW EXECUTE FUNCTION artifact_metadata_guard();
ALTER TABLE database_artifact DISABLE TRIGGER artifact_metadata_guard;

-- Payload deletion is one chunk/statement. The owner lock is shared with
-- reservations, legacy writers and pointer publication. 'deleting' is a fence:
-- time determines eligibility, never permission to resume or publish a part.
CREATE FUNCTION artifact_reap_one(p_service text,p_space text,p_name text,p_id text,
 abort_upload boolean DEFAULT false) RETURNS boolean LANGUAGE plpgsql SET lock_timeout='50ms' AS $$
DECLARE p artifact_part%ROWTYPE; next_ordinal integer; child_credit bigint;
BEGIN
 SELECT * INTO p FROM artifact_part WHERE service=p_service AND space=p_space AND name=p_name AND part_id=p_id;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM artifact_account WHERE owner=p.owner FOR UPDATE;
 SELECT * INTO p FROM artifact_part WHERE service=p_service AND space=p_space
   AND name=p_name AND part_id=p_id FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM database_artifact d WHERE d.service=p.service
   AND d.space=p.space AND d.name=p.name AND
   (d.checkpoint_part_id=p.part_id OR d.delta_part_id=p.part_id)) THEN RETURN false; END IF;
 IF NOT abort_upload AND p.state<>'deleting' AND p.lease_until>clock_timestamp() THEN RETURN false; END IF;
 UPDATE artifact_part SET state='deleting',lease_until=clock_timestamp() WHERE service=p.service AND space=p.space AND name=p.name AND part_id=p.part_id;
 SELECT ordinal INTO next_ordinal FROM artifact_chunk WHERE service=p.service AND space=p.space
   AND name=p.name AND part_id=p.part_id ORDER BY ordinal LIMIT 1;
 IF FOUND THEN DELETE FROM artifact_chunk WHERE service=p.service AND space=p.space
   AND name=p.name AND part_id=p.part_id AND ordinal=next_ordinal; END IF;
 IF NOT EXISTS(SELECT 1 FROM artifact_chunk WHERE service=p.service AND space=p.space AND name=p.name AND part_id=p.part_id) THEN
   SELECT COALESCE(sum(replacement_credit),0) INTO child_credit FROM artifact_part
    WHERE service=p.service AND space=p.space AND name=p.name AND replaces_part_id=p.part_id;
   UPDATE artifact_part SET replacement_credit=0,replacing=false,replaces_part_id=NULL
    WHERE service=p.service AND space=p.space AND name=p.name AND replaces_part_id=p.part_id;
   DELETE FROM artifact_part WHERE service=p.service AND space=p.space AND name=p.name AND part_id=p.part_id;
   UPDATE artifact_account SET reserved_bytes=reserved_bytes-p.size_bytes,
     credit_bytes=credit_bytes-p.replacement_credit-child_credit WHERE owner=p.owner;
 END IF;
 RETURN true;
END $$;

CREATE FUNCTION artifact_metadata_retire() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE released bigint;
BEGIN
 IF TG_OP='DELETE' THEN
   SELECT COALESCE(sum(replacement_credit),0) INTO released FROM artifact_part
     WHERE service=OLD.service AND space=OLD.space AND name=OLD.name;
   UPDATE artifact_part SET state='deleting',lease_until=clock_timestamp(),replacement_credit=0,replacing=false,replaces_part_id=NULL
     WHERE service=OLD.service AND space=OLD.space AND name=OLD.name;
   IF released>0 THEN UPDATE artifact_account SET credit_bytes=credit_bytes-released
     WHERE owner=artifact_owner(OLD.space); END IF;
   RETURN OLD;
 END IF;
 IF OLD.checkpoint_part_id IS DISTINCT FROM NEW.checkpoint_part_id THEN
   IF OLD.checkpoint_part_id IS NOT NULL THEN
     UPDATE artifact_part SET state='deleting',lease_until=clock_timestamp() WHERE service=OLD.service AND space=OLD.space
       AND name=OLD.name AND part_id=OLD.checkpoint_part_id;
   ELSE
     SELECT replacement_credit INTO released FROM artifact_part WHERE service=NEW.service
       AND space=NEW.space AND name=NEW.name AND part_id=NEW.checkpoint_part_id;
     UPDATE artifact_part SET replacement_credit=0,replacing=false WHERE service=NEW.service
       AND space=NEW.space AND name=NEW.name AND part_id=NEW.checkpoint_part_id;
     IF released>0 THEN UPDATE artifact_account SET credit_bytes=credit_bytes-released
       WHERE owner=artifact_owner(NEW.space); END IF;
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER artifact_metadata_retire AFTER UPDATE OR DELETE ON database_artifact
 FOR EACH ROW EXECUTE FUNCTION artifact_metadata_retire();
ALTER TABLE database_artifact DISABLE TRIGGER artifact_metadata_retire;

CREATE FUNCTION artifact_reserve(p_service text,p_space text,p_name text,p_id text,p_owner text,
 p_size bigint,p_count integer,p_revision bigint,p_hash text)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE base record; existing boolean; credit bigint:=0; cap bigint;
BEGIN
 IF p_owner<>artifact_owner(p_space) THEN RAISE EXCEPTION 'TC2917_LAYOUT: owner mismatch'; END IF;
 PERFORM 1 FROM artifact_account WHERE owner=p_owner FOR UPDATE;
 SELECT revision,size_bytes,checkpoint_content_hash,checkpoint_part_id INTO base FROM database_artifact WHERE service=p_service AND space=p_space AND name=p_name;
 existing:=FOUND;
 IF (p_revision IS NULL AND existing) OR (p_revision IS NOT NULL AND
   (NOT existing OR base.revision<>p_revision OR base.checkpoint_content_hash<>p_hash)) THEN
   RAISE EXCEPTION 'TC2917_LAYOUT: superseded reservation';
 END IF;
 IF EXISTS(SELECT 1 FROM artifact_part WHERE service=p_service AND space=p_space
   AND name=p_name AND replacing) THEN RETURN false; END IF;
 IF existing THEN credit:=LEAST(base.size_bytes,p_size); END IF;
 SELECT account_limit INTO cap FROM artifact_storage_settings WHERE id=1;
 -- Pending shrinkage never creates spare quota for another database: the
 -- ledger credits only overlapping bytes, not the shrink's eventual saving.
 UPDATE artifact_account SET reserved_bytes=reserved_bytes+p_size,credit_bytes=credit_bytes+credit
 WHERE owner=p_owner AND ((existing AND p_size<=base.size_bytes) OR
   legacy_bytes+reserved_bytes-credit_bytes
   -CASE WHEN existing THEN base.size_bytes ELSE 0 END+p_size<=cap);
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO artifact_part(service,space,name,part_id,owner,size_bytes,chunk_count,
   replacement_credit,replacing,replaces_part_id)
 VALUES(p_service,p_space,p_name,p_id,p_owner,p_size,p_count,credit,existing,
   CASE WHEN existing THEN base.checkpoint_part_id ELSE NULL END);
 RETURN true;
END $$;

CREATE FUNCTION artifact_metadata_publish() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.checkpoint_part_id IS NOT NULL THEN
   UPDATE artifact_part SET state='published',lease_until='infinity'::timestamptz
    WHERE service=NEW.service AND space=NEW.space AND name=NEW.name
      AND part_id=NEW.checkpoint_part_id AND state='sealed';
   IF NOT EXISTS(SELECT 1 FROM artifact_part WHERE service=NEW.service AND space=NEW.space
      AND name=NEW.name AND part_id=NEW.checkpoint_part_id AND state='published') THEN
     RAISE EXCEPTION 'TC2917_LAYOUT: unpublished part';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER artifact_metadata_publish AFTER INSERT OR UPDATE ON database_artifact
 FOR EACH ROW EXECUTE FUNCTION artifact_metadata_publish();

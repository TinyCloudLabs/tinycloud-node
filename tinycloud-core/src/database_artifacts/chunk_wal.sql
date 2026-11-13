ALTER TABLE artifact_part ADD COLUMN replaces_delta_part_id text;
ALTER TABLE artifact_part ADD CONSTRAINT artifact_part_replaced_delta_fk
 FOREIGN KEY(service,space,name,replaces_delta_part_id) REFERENCES artifact_part(service,space,name,part_id);
CREATE OR REPLACE FUNCTION artifact_layout_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND OLD.checkpoint_part_id IS NOT NULL THEN
   IF NEW.checkpoint_part_id IS NULL OR NEW.storage_mode<>'checkpoint-parts-v1'
      OR NEW.layout_generation<>OLD.layout_generation+1
      OR NEW.revision<>OLD.revision+1
      OR (NEW.checkpoint_part_id,NEW.delta_part_id) IS NOT DISTINCT FROM (OLD.checkpoint_part_id,OLD.delta_part_id) THEN
     RAISE EXCEPTION 'TC2917_LAYOUT: legacy writes cannot replace checkpoint parts';
   END IF;
 END IF;
 IF TG_OP<>'DELETE' AND NEW.checkpoint_part_id IS NOT NULL THEN
   IF NEW.storage_mode<>'checkpoint-parts-v1' OR NEW.delta_payload IS NOT NULL OR octet_length(NEW.payload)<>0
      OR (NEW.delta_part_id IS NULL)<>(NEW.delta_content_hash IS NULL)
      OR (NEW.delta_part_id IS NULL AND NEW.delta_size_bytes<>0) THEN
     RAISE EXCEPTION 'TC2917_LAYOUT: invalid checkpoint layout';
   END IF;
   IF TG_OP='INSERT' AND NEW.layout_generation<>1 THEN RAISE EXCEPTION 'TC2917_LAYOUT: invalid generation'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE FUNCTION artifact_reserve_part(p_service text,p_space text,p_name text,p_id text,p_owner text,
 p_size bigint,p_count integer,p_revision bigint,p_hash text,p_wal boolean)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE base record; existing boolean; credit bigint:=0; cap bigint; part_cap bigint; replaced bigint:=0;
BEGIN
 IF p_owner<>artifact_owner(p_space) THEN RAISE EXCEPTION 'TC2917_LAYOUT: owner mismatch'; END IF;
 PERFORM 1 FROM artifact_account WHERE owner=p_owner FOR UPDATE;
 SELECT revision,size_bytes,checkpoint_size_bytes,delta_size_bytes,checkpoint_content_hash,checkpoint_part_id,delta_part_id INTO base FROM database_artifact WHERE service=p_service AND space=p_space AND name=p_name;
 existing:=FOUND;
 IF (p_revision IS NULL AND existing) OR (p_revision IS NOT NULL AND
   (NOT existing OR base.revision<>p_revision OR base.checkpoint_content_hash<>p_hash)) THEN
   RAISE EXCEPTION 'TC2917_LAYOUT: superseded reservation';
 END IF;
 IF p_wal AND (NOT existing OR base.checkpoint_part_id IS NULL) THEN RAISE EXCEPTION 'TC2917_LAYOUT: missing checkpoint'; END IF;
 IF EXISTS(SELECT 1 FROM artifact_part WHERE service=p_service AND space=p_space AND name=p_name AND replacing) THEN RETURN false; END IF;
 SELECT account_limit,artifact_limit INTO cap,part_cap FROM artifact_storage_settings WHERE id=1;
 IF p_size<0 OR p_count<>((p_size+1048575)/1048576) OR
    p_size+(CASE WHEN p_wal THEN base.checkpoint_size_bytes ELSE 0 END)>part_cap THEN RETURN false; END IF;
 IF existing THEN replaced:=CASE WHEN p_wal THEN base.delta_size_bytes ELSE base.size_bytes END; END IF;
 credit:=LEAST(replaced,p_size);
 UPDATE artifact_account SET reserved_bytes=reserved_bytes+p_size,credit_bytes=credit_bytes+credit
 WHERE owner=p_owner AND ((existing AND p_size<=replaced) OR
   legacy_bytes+reserved_bytes-credit_bytes-replaced+p_size<=cap);
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO artifact_part(service,space,name,part_id,owner,size_bytes,chunk_count,
   replacement_credit,replacing,replaces_part_id,replaces_delta_part_id)
 VALUES(p_service,p_space,p_name,p_id,p_owner,p_size,p_count,credit,existing,
   CASE WHEN existing THEN CASE WHEN p_wal THEN base.delta_part_id ELSE base.checkpoint_part_id END ELSE NULL END,
   CASE WHEN existing AND NOT p_wal THEN base.delta_part_id ELSE NULL END);
 RETURN true;
END $$;
CREATE OR REPLACE FUNCTION artifact_reserve(p_service text,p_space text,p_name text,p_id text,p_owner text,
 p_size bigint,p_count integer,p_revision bigint,p_hash text) RETURNS boolean LANGUAGE sql AS $$
 SELECT artifact_reserve_part(p_service,p_space,p_name,p_id,p_owner,p_size,p_count,p_revision,p_hash,false)
$$;
CREATE OR REPLACE FUNCTION artifact_reap_one(p_service text,p_space text,p_name text,p_id text,
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
   -- Reduce overlapping credit only after this whole old part is gone.
   -- Keeping its credit after removing its byte charge would undercount live
   -- usage while another retired part is still awaiting collection.
   SELECT COALESCE(sum(LEAST(replacement_credit,p.size_bytes)),0) INTO child_credit FROM artifact_part
    WHERE service=p.service AND space=p.space AND name=p.name
      AND (replaces_part_id=p.part_id OR replaces_delta_part_id=p.part_id);
   UPDATE artifact_part SET replacement_credit=replacement_credit-LEAST(replacement_credit,p.size_bytes),
     replaces_part_id=CASE WHEN replaces_part_id=p.part_id THEN NULL ELSE replaces_part_id END,
     replaces_delta_part_id=CASE WHEN replaces_delta_part_id=p.part_id THEN NULL ELSE replaces_delta_part_id END
    WHERE service=p.service AND space=p.space AND name=p.name
      AND (replaces_part_id=p.part_id OR replaces_delta_part_id=p.part_id);
   UPDATE artifact_part SET replacing=false
    WHERE service=p.service AND space=p.space AND name=p.name AND state='published'
      AND replaces_part_id IS NULL AND replaces_delta_part_id IS NULL AND replacement_credit=0;
   DELETE FROM artifact_part WHERE service=p.service AND space=p.space AND name=p.name AND part_id=p.part_id;
   UPDATE artifact_account SET reserved_bytes=reserved_bytes-p.size_bytes,
     credit_bytes=credit_bytes-p.replacement_credit-child_credit WHERE owner=p.owner;
 END IF;
 RETURN true;
END $$;
CREATE OR REPLACE FUNCTION artifact_metadata_retire() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE released bigint;
BEGIN
 IF TG_OP='DELETE' THEN
   SELECT COALESCE(sum(replacement_credit),0) INTO released FROM artifact_part
     WHERE service=OLD.service AND space=OLD.space AND name=OLD.name;
   UPDATE artifact_part SET state='deleting',lease_until=clock_timestamp(),replacement_credit=0,replacing=false,replaces_part_id=NULL,replaces_delta_part_id=NULL
     WHERE service=OLD.service AND space=OLD.space AND name=OLD.name;
   IF released>0 THEN UPDATE artifact_account SET credit_bytes=credit_bytes-released
     WHERE owner=artifact_owner(OLD.space); END IF;
   RETURN OLD;
 END IF;
 IF OLD.delta_part_id IS NOT NULL AND OLD.delta_part_id IS DISTINCT FROM NEW.delta_part_id THEN
   UPDATE artifact_part SET state='deleting',lease_until=clock_timestamp() WHERE service=OLD.service AND space=OLD.space
    AND name=OLD.name AND part_id=OLD.delta_part_id;
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
CREATE OR REPLACE FUNCTION artifact_metadata_publish() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE artifact_part SET state='published',lease_until='infinity'::timestamptz
  WHERE service=NEW.service AND space=NEW.space AND name=NEW.name
    AND part_id IN (NEW.checkpoint_part_id,NEW.delta_part_id) AND state='sealed';
 IF NEW.checkpoint_part_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM artifact_part WHERE service=NEW.service AND space=NEW.space
   AND name=NEW.name AND part_id=NEW.checkpoint_part_id AND state='published') THEN RAISE EXCEPTION 'TC2917_LAYOUT: unpublished checkpoint'; END IF;
 IF NEW.delta_part_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM artifact_part WHERE service=NEW.service AND space=NEW.space
   AND name=NEW.name AND part_id=NEW.delta_part_id AND state='published') THEN RAISE EXCEPTION 'TC2917_LAYOUT: unpublished WAL'; END IF;
 UPDATE artifact_part SET replacing=false WHERE service=NEW.service AND space=NEW.space AND name=NEW.name
   AND state='published' AND replaces_part_id IS NULL AND replaces_delta_part_id IS NULL AND replacement_credit=0;
 RETURN NEW;
END $$;

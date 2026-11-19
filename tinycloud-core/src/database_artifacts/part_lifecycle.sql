CREATE INDEX artifact_part_reap_database ON artifact_part(service,space,name,lease_until) WHERE state<>'published';
CREATE OR REPLACE FUNCTION artifact_reserve_part(p_service text,p_space text,p_name text,p_id text,p_owner text,
 p_size bigint,p_count integer,p_revision bigint,p_hash text,p_wal boolean)
RETURNS boolean LANGUAGE plpgsql SET lock_timeout='50ms' AS $$
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
 IF EXISTS(SELECT 1 FROM artifact_part WHERE service=p_service AND space=p_space AND name=p_name AND replacing) THEN RAISE EXCEPTION USING ERRCODE='TC001', MESSAGE='TC2917_BUSY'; END IF;
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
EXCEPTION WHEN lock_not_available THEN
 RAISE EXCEPTION USING ERRCODE='TC001', MESSAGE='TC2917_BUSY';
END $$;

CREATE OR REPLACE FUNCTION artifact_metadata_publish() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.checkpoint_part_id IS NULL THEN RETURN NEW; END IF;
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

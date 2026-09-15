#!/usr/bin/env python3
"""Conservative, read-only rollback inventory. Output contains aggregate counts only.

The native protocol always creates the literal connector_publication_ tables.
Search BOTH durable checkpoint and WAL bytes in Postgres without exporting
other users' database contents. A possible match outside the target blocks
withdrawal even when it might only be an inactive or deleted schema remnant.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import re
from datetime import datetime, timezone

TARGET = '8aa0096ee9d8c64b2f59bfb7b1e6a0e7b32863948e4eb52f549b0d9927a7bb61'
SQL = r"""
BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '45s';
WITH raw AS (
 SELECT *, CASE WHEN substring(payload FROM 17 FOR 2)=decode('0001','hex') THEN 65536
   WHEN octet_length(payload)>=100 THEN get_byte(payload,16)*256+get_byte(payload,17)
   ELSE 0 END AS page_size
 FROM database_artifact WHERE service='sql' AND name='connectors'
), a AS (
 SELECT encode(sha256(convert_to(space,'UTF8')),'hex') =
 '8aa0096ee9d8c64b2f59bfb7b1e6a0e7b32863948e4eb52f549b0d9927a7bb61' AS target,
 EXISTS (SELECT 1 FROM (VALUES
   (convert_to('connector_publication_','UTF8')),
   (decode('63006f006e006e006500630074006f0072005f007000750062006c00690063006100740069006f006e005f00','hex')),
   (decode('0063006f006e006e006500630074006f0072005f007000750062006c00690063006100740069006f006e005f','hex'))
 ) AS markers(marker)
 WHERE position(marker IN payload)>0 OR position(marker IN coalesce(delta_payload,''::bytea))>0) AS candidate,
 (substring(payload FROM 1 FOR 16) = decode('53514c69746520666f726d6174203300','hex')
  AND page_size IN (512,1024,2048,4096,8192,16384,32768,65536)
  AND octet_length(payload)>=page_size
  AND octet_length(payload)%NULLIF(page_size,0)=0
  AND substring(payload FROM 57 FOR 4) IN (decode('00000000','hex'),decode('00000001','hex'),decode('00000002','hex'),decode('00000003','hex'))
  AND octet_length(payload)=checkpoint_size_bytes
  AND storage_mode IN ('database-blob','checkpoint+wal')
  AND ((delta_payload IS NULL AND delta_size_bytes=0 AND storage_mode='database-blob') OR
       (delta_payload IS NOT NULL AND storage_mode='checkpoint+wal'
        AND octet_length(delta_payload)=delta_size_bytes
        AND octet_length(delta_payload)>=32+24+page_size
        AND (octet_length(delta_payload)-32)%NULLIF(24+page_size,0)=0
        AND substring(delta_payload FROM 9 FOR 4)=decode(lpad(to_hex(page_size),8,'0'),'hex')
        AND substring(delta_payload FROM 1 FOR 4) IN (decode('377f0682','hex'),decode('377f0683','hex'))))) AS valid
 FROM raw
), guards AS (
 SELECT encode(sha256(convert_to(space,'UTF8')),'hex') =
 '8aa0096ee9d8c64b2f59bfb7b1e6a0e7b32863948e4eb52f549b0d9927a7bb61' AS target,
 frozen,generation FROM meeting_legacy_write_guard
)
SELECT json_build_object(
 'connectorsDatabases',count(*),
 'targetDatabases',count(*) FILTER (WHERE target),
 'targetPublicationCandidates',count(*) FILTER (WHERE target AND candidate),
 'otherPublicationCandidates',count(*) FILTER (WHERE NOT target AND candidate),
 'invalidArtifacts',count(*) FILTER (WHERE valid IS NOT TRUE),
 'targetFrozenGenerationOne',(SELECT count(*) FROM guards WHERE target AND frozen AND generation=1),
 'otherUsedGuards',(SELECT count(*) FROM guards WHERE NOT target AND (frozen OR generation<>0))
)::text FROM a;
ROLLBACK;
"""

def main():
    dsn = os.environ.get('RECOVERY_DATABASE_URL')
    if not dsn:
        print(json.dumps({'passed': False, 'code': 'DATABASE_ACCESS_UNAVAILABLE'}))
        return 1
    env = dict(os.environ, PGCONNECT_TIMEOUT='15', PGOPTIONS='-c default_transaction_read_only=on')
    try:
        result = subprocess.run(['psql', '--no-psqlrc', '--quiet', '--tuples-only', '--no-align',
                                 '--set=ON_ERROR_STOP=1', '--set=VERBOSITY=sqlstate', '--dbname', dsn],
                                input=SQL, text=True, capture_output=True, env=env, timeout=65)
        if result.returncode:
            # Do not dump libpq diagnostics, connection data or other user data.
            sqlstate = re.search(r'\b(?:ERROR|FATAL):\s+([0-9A-Z]{5})\b', result.stderr)
            categories = [('invalid URI query parameter', 'UNSUPPORTED_DSN_PARAMETER'),
                          ('could not translate host name', 'DNS_LOOKUP_FAILED'),
                          ('Connection refused', 'CONNECTION_REFUSED'),
                          ('timeout expired', 'CONNECTION_TIMED_OUT'),
                          ('password authentication failed', 'AUTHENTICATION_FAILED'),
                          ('invalid connection option', 'UNSUPPORTED_DSN_OPTION')]
            diagnostic = next((code for marker, code in categories if marker in result.stderr), None)
            print(json.dumps({'queryFailed': True, 'sqlstate': sqlstate.group(1) if sqlstate else None,
                              'connectionCategory': diagnostic}))
            raise RuntimeError('AUDIT_QUERY_FAILED')
        counts = json.loads(result.stdout.strip())
        expected = {'connectorsDatabases','targetDatabases','targetPublicationCandidates',
                    'otherPublicationCandidates','invalidArtifacts','targetFrozenGenerationOne','otherUsedGuards'}
        if set(counts) != expected or any(type(v) is not int or v < 0 for v in counts.values()):
            raise RuntimeError('AUDIT_RESPONSE_INVALID')
        passed = (counts['targetDatabases'] == 1 and counts['targetPublicationCandidates'] == 1
                  and counts['otherPublicationCandidates'] == 0 and counts['invalidArtifacts'] == 0
                  and counts['targetFrozenGenerationOne'] == 1 and counts['otherUsedGuards'] == 0)
        report = {'checkedAt': datetime.now(timezone.utc).isoformat(), 'mutationRequested': False,
                  'targetSpaceSha256': TARGET, 'counts': counts, 'passed': passed,
                  'scope': 'Conservative schema-marker inventory of SQL connectors checkpoints and WAL; no user database bytes exported'}
        Path('meeting-rollback-audit.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))
        return 0 if passed else 1
    except Exception as error:
        allowed = {'AUDIT_QUERY_FAILED','AUDIT_RESPONSE_INVALID'}
        code = str(error) if str(error) in allowed else 'AUDIT_EXECUTION_FAILED'
        print(json.dumps({'passed': False, 'code': code}))
        return 1

if __name__ == '__main__':
    sys.exit(main())

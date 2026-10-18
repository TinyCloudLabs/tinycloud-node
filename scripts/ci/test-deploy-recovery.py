#!/usr/bin/env python3
"""Run actual workflow Bash against offline CLI/HTTP boundaries only."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / ".github/workflows/docker.yml").read_text()
DIGEST = "sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f"
REVISION = "e18578ff9162986ddd813259c60f73866e3e60d1"
# The real PROD_TINYCLOUD_QUOTA_URL shape: billing's bare HTTPS origin, not a /api/quota path.
BILLING_URL = "https://billing.example.invalid"
N0 = (ROOT / "scripts/ci/fixtures/tc959-n0-compose.yaml").read_bytes()
PRE_N0 = (ROOT / "ops/rollback/pre-n0-compose.yaml").read_bytes()
STOP_LOGS = (ROOT / "ops/rollback/pre-n0-stop-local-logs.yaml").read_bytes()
CURRENT = (ROOT / "docker-compose.dstack-postgres.yaml").read_bytes()
# Ordinary (pre-N0) template from main before #309: the captured rollback compose with its digest pin
# reverted to the :dstack tag. The workflow accepts these bytes by raw hash.
PRE_N0_TEMPLATE = PRE_N0.replace(b"@" + DIGEST.encode(), b":dstack")
assert hashlib.sha256(PRE_N0_TEMPLATE).hexdigest() == "28302d6761d841b7cc5c11314aed2d377735e6bbdcaf85972a752e03bc9fdc93"
RELEASE_DIGEST = "sha256:" + "b" * 64
RELEASE_REVISION = "c" * 40
RELEASE = {"deploy_image_digest": RELEASE_DIGEST, "image_version": "1.21.0",
           "rollback_image_version": "1.21.0", "rollback_image_revision": RELEASE_REVISION}
RELEASED = {"1.21.0": (RELEASE_REVISION, "1.21.0")}
RELEASE_N0 = N0.replace(DIGEST.encode(), RELEASE_DIGEST.encode())
OLD_REVISION = "a" * 40
ANCIENT_REVISION = "9" * 40
ORDER = [ANCIENT_REVISION, OLD_REVISION, REVISION, RELEASE_REVISION]
CANARIES = []


def shell_for_step(name):
    marker = "      - name: " + name + "\n"
    block = SOURCE.split(marker, 1)[1]
    lines = []
    for line in block.split("        run: |\n", 1)[1].splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


def enabled(condition, context):
    literals = []
    def protect(match):
        literals.append(match[0])
        return f"@{len(literals)-1}@"
    condition = re.sub(r"'[^']*'", protect, condition)
    condition = re.sub(r"(?:github|inputs|steps|needs|vars)\.[\w.-]+(?:\.[\w.-]+)*",
                       lambda match: repr(context.get(match[0], "")), condition)
    condition = condition.replace("success()", repr(context.get("job.success", True)))
    condition = condition.replace("always()", "True").replace("cancelled()", "False")
    condition = re.sub(r"!(?!=)", "not ", condition).replace("&&", " and ").replace("||", " or ")
    for index, literal in enumerate(literals):
        condition = condition.replace(f"@{index}@", literal)
    return bool(eval("(" + condition + ")", {"__builtins__": {}}, {}))


def step_enabled(name, context):
    block = SOURCE.split("      - name: " + name + "\n", 1)[1]
    prefix = block.split("        run:", 1)[0]
    if not context["job.success"] and "always()" not in prefix:
        return False
    if "        if: >-\n" in prefix:
        condition = prefix.split("        if: >-\n", 1)[1].split("\n        env:", 1)[0].strip()[3:-2]
    elif "        if: " in prefix:
        condition = prefix.split("        if: ", 1)[1].split("\n", 1)[0].strip()
        if condition.startswith("${{"):
            condition = condition[3:-2]
    else:
        return context["job.success"]
    return enabled(condition, context)


CLI = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args=sys.argv[1:]; name=Path(sys.argv[0]).name
state=Path(os.environ['TEST_STATE'])
def event(value):
    data=json.loads(state.read_text()); data['events'].append(value); state.write_text(json.dumps(data))
if name=='docker':
    if args[0]=='pull': event('image-pull')
    elif args[:2]==['image','inspect']:
        print(os.environ['OCI_REVISION'] if 'revision' in args[-1] else os.environ['OCI_LABEL'])
    elif args[0]=='run':
        assert args[-1]=='--validate-config' and 'none' in args and '--read-only' in args; event('sealed-preflight')
    elif args[0]=='compose':
        assert args[-2:]==['config','--quiet']; assert Path('.phala-prod.env').stat().st_mode & 0o777==0o600
    else: raise SystemExit('Unexpected Docker boundary')
elif name=='git':
    releases=json.loads(os.environ['TEST_RELEASES'])
    if args==['rev-parse','HEAD']: print('f'*40)
    elif args[:2]==['merge-base','--is-ancestor'] and len(args)==4:
        order=json.loads(os.environ['TEST_ORDER'])
        ok=args[2] in order and args[3] in order and order.index(args[2])<=order.index(args[3])
        sys.exit(0 if ok else 1)
    elif args[:3]==['rev-parse','--verify','--quiet'] and len(args)==4:
        tag=args[3]; assert tag.startswith('refs/tags/v') and tag.endswith('^{commit}')
        release=releases.get(tag[len('refs/tags/v'):-len('^{commit}')])
        if release is None: sys.exit(1)
        print(release[0])
    elif args[0]=='show' and len(args)==2:
        revision,path=args[1].split(':',1); assert path=='tinycloud-node-server/Cargo.toml'
        crates=[crate for tagged,crate in releases.values() if tagged==revision]
        if not crates: sys.exit(128)
        print('[package]\nname = "tinycloud-node"\nversion = "'+crates[0]+'"')
    else: raise SystemExit('Unexpected git boundary')
elif name=='node':
    names=[line.split('=',1)[0] for line in Path('.phala-prod.env').read_text().splitlines()]
    assert 'BETTERSTACK_SOURCE_TOKEN' in names and 'QUOTA_BILLING_ADMIN_SECRET' not in names
    if args[-1]=='--check': event('whitelist-check')
    else:
        event('whitelist-sync')
        if os.environ['FAIL_AT']=='sync': raise SystemExit('Fixed synchronization failure')
        event('final-restart')
elif name=='phala':
    assert args[:3]==['deploy','--cvm-id','tinycloud-node']
    assert '--no-public-logs' in args and '--no-public-sysinfo' in args
    event('cvm-deploy')
    if os.environ['FAIL_AT']=='deploy':
        print(os.environ['PHALA_ENV_BETTERSTACK_SOURCE_TOKEN'],file=sys.stderr); sys.exit(1)
elif name=='curl':
    url=next(value for value in args if value.startswith('https://'))
    if url.endswith('/version'):
        event('ingress-health' if 'tee.node.' in url else 'version-health')
        print(json.dumps({'version':'not-ready' if os.environ['FAIL_AT']=='health' else os.environ['OCI_LABEL'].split('-dstack')[0]}))
    else:
        assert url.startswith('https://tee.node.tinycloud.xyz/policy/v3/')
        if '-o' in args: Path(args[args.index('-o')+1]).write_text('{}')
        event('policy-probe'); print('500' if os.environ['FAIL_AT']=='policy' else ('401' if url.endswith('/deliveries/authorize') else '400'),end='')
elif name=='sleep': pass
else: raise SystemExit('Unexpected CLI boundary')
'''

HTTP = r'''import http.client, io, json, os, random, socket
from pathlib import Path
from urllib.parse import unquote
socket.create_connection=lambda *a,**k: (_ for _ in ()).throw(AssertionError('Real network forbidden'))
class Connection:
    def __init__(self,host,timeout,**kwargs):
        assert host in ('node.tinycloud.xyz','billing.example.invalid'); self.host=host
    def request(self,method,path,body=None,headers=None):
        expected=os.environ['QUOTA_BILLING_ADMIN_SECRET'] if self.host=='billing.example.invalid' else os.environ['QUOTA_ADMIN_SECRET']
        assert headers['Authorization']=='Bearer '+expected
        assert self.host!='billing.example.invalid' or path.startswith('/api/admin/storage-comp/')
        self.method,self.path=method,path
        state=Path(os.environ['TEST_STATE']); data=json.loads(state.read_text())
        if self.host=='billing.example.invalid': data['events'].append('billing-comp')
        elif path=='/admin/usage': data['events'].append('quota-inventory')
        elif method=='PUT': data['events'].append('quota-put'); data['values'][path]=json.loads(body)['limit_bytes']
        elif method=='DELETE': raise AssertionError('Node override deletion is forbidden')
        else: data['events'].append('quota-readback')
        state.write_text(json.dumps(data))
    def getresponse(self):
        data=json.loads(Path(os.environ['TEST_STATE']).read_text())
        rows=json.loads(Path('ops/quota-overrides.json').read_text())
        targets=rows.get('overrides',rows)
        status=200
        if self.host=='billing.example.invalid':
            if rows.get('authority')=='billing':
                floor=targets[unquote(self.path.rsplit('/',1)[1])]['limit_bytes']
                payload={'active':True,'comp_bytes':1,'account_limit_bytes':floor+100,'storage_limit_bytes':floor+100}
            else: status,payload=404,os.environ['QUOTA_BILLING_ADMIN_SECRET']
        elif os.environ['FAIL_AT']=='quota': status,payload=503,os.environ['QUOTA_ADMIN_SECRET']
        elif self.path=='/admin/usage':
            # The node's real, unpaginated inventory: every space, ~107 bytes a row (prod: ~1,034 spaces).
            rng=random.Random(959); spaces=[{'space_id':space,'usage_bytes':10} for space in targets]
            spaces+=[{'space_id':'tinycloud:pkh:eip155:1:0x%040x:default'%rng.getrandbits(160),'usage_bytes':rng.choice([None,rng.randint(1,700000000)])} for _ in range(3000)]
            payload={'spaces':spaces,'count':len(spaces)}
        else:
            value=data['values'].get(self.path)
            payload={'space_id':unquote(self.path.removeprefix('/admin/quota/')),'override_bytes':value,'effective_limit_bytes':value if value is not None else 123}
        stream=io.BytesIO(json.dumps(payload).encode())
        class Response:
            def read(self,count): return stream.read(count)
        response=Response(); response.status=status; return response
    def close(self): pass
http.client.HTTPSConnection=Connection
'''


class SafeResult(unittest.TextTestResult):
    def _exc_info_to_string(self, error, test):
        text = super()._exc_info_to_string(error, test)
        for value in CANARIES:
            text = text.replace(value, "[withheld]")
        return text


class RecoveryTests(unittest.TestCase):
    def run_deploy(self, compose=CURRENT, changes=None, *, fail_at="", artifact_error="", authority="node-override",
                   missing_billing=False, missing_authorization=False, approved_privacy="", event="workflow_dispatch",
                   ref="refs/heads/main", oci_label=None, oci_revision=None, build_digest="", releases=RELEASED, running=REVISION, order=None):
        inputs = {"deploy_phala": "true", "authorize_quota_values": "true", "image_version": "1.20.6",
                  "deploy_image_digest": DIGEST, "rollback_image_version": "1.20.6", "rollback_image_revision": REVISION,
                  "rollback_pre_n0": "false", "rollback_privacy_mode": "unselected", "sql_identity_fence": "false"}
        inputs.update(changes or {})
        if missing_authorization:
            inputs.pop("authorize_quota_values", None)
        canary = secrets.token_urlsafe(32)
        CANARIES.append(canary)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binaries = root / "bin"; binaries.mkdir()
            for name in ("docker", "git", "node", "phala", "curl", "sleep"):
                binary = binaries / name; binary.write_text(CLI); binary.chmod(0o700)
            (root / "sitecustomize.py").write_text(HTTP)
            (root / "tinycloud-node-server").mkdir()
            (root / "tinycloud-node-server/Cargo.toml").write_text('version = "1.20.7"\n')
            (root / "dstack-authorized-keys").write_text("synthetic-public-key\n")
            (root / "phala-env-sync").mkdir()
            (root / "scripts/ci").mkdir(parents=True)
            (root / "scripts/ci/reconcile-quota.py").write_bytes((ROOT / "scripts/ci/reconcile-quota.py").read_bytes())
            (root / "ops/rollback").mkdir(parents=True)
            for filename, content in (("pre-n0-compose.yaml", PRE_N0), ("pre-n0-stop-local-logs.yaml", STOP_LOGS)):
                (root / "ops/rollback" / filename).write_bytes(content)
            base_artifact = root / "ops/rollback/pre-n0-compose.yaml"
            if artifact_error == "drift": base_artifact.write_bytes(PRE_N0 + b"\n# drift\n")
            if artifact_error == "missing": base_artifact.unlink()
            if artifact_error == "symlink":
                base_artifact.unlink(); (root / "alternate.yaml").write_bytes(PRE_N0); base_artifact.symlink_to(root / "alternate.yaml")
            if artifact_error == "stop-drift": (root / "ops/rollback/pre-n0-stop-local-logs.yaml").write_bytes(STOP_LOGS + b"\n# drift\n")
            config = json.loads((ROOT / "ops/quota-overrides.json").read_text())
            config["authority"] = authority
            if authority is None: config.pop("authority")
            (root / "ops/quota-overrides.json").write_text(json.dumps(config))
            compose_path = root / "docker-compose.dstack-postgres.yaml"; compose_path.write_bytes(compose)
            if artifact_error == "root-symlink":
                compose_path.unlink(); (root / "destination.yaml").write_bytes(compose); compose_path.symlink_to(root / "destination.yaml")
            state = root / "state"; state.write_text(json.dumps({"events": [], "values": {}}))
            output = root / "output"; summary = root / "summary"
            deploy = shell_for_step("Deploy to Phala Cloud")
            required = deploy.split("required_vars=(\n", 1)[1].split("\n)", 1)[0].split()
            env = {name: canary for name in required}
            env.update({"PATH": str(binaries) + ":" + str(Path(sys.executable).parent) + ":/usr/bin:/bin",
                        "PYTHONPATH": directory, "TMPDIR": directory, "RUNNER_TEMP": directory, "TEST_STATE": str(state),
                        "FAIL_AT": fail_at, "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary),
                        "REGISTRY": "ghcr.io", "IMAGE_NAME": "tinycloudlabs/tinycloud-node", "BUILD_DIGEST": build_digest,
                        "EVENT_NAME": event, "GITHUB_REF": ref, "GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main", "RELEASE_TAG": "",
                        "INPUT_DEPLOY_PHALA": inputs["deploy_phala"], "AUTHORIZE_QUOTA_VALUES": inputs.get("authorize_quota_values", "false"),
                        "INPUT_IMAGE_VERSION": inputs["image_version"], "INPUT_DEPLOY_DIGEST": inputs["deploy_image_digest"],
                        "ROLLBACK_VERSION": inputs.get("rollback_image_version", ""), "ROLLBACK_REVISION": inputs.get("rollback_image_revision", ""),
                        "ROLLBACK_PRE_N0": inputs["rollback_pre_n0"], "ROLLBACK_PRIVACY_MODE": inputs["rollback_privacy_mode"],
                        "APPROVED_ROLLBACK_PRIVACY_MODE": approved_privacy, "INCLUDE_DUCKDB": "false", "INCLUDE_TC_BENCH_V1": "false",
                        "DEPLOY_VERSION": inputs["image_version"], "OCI_LABEL": oci_label or inputs["image_version"] + "-dstack",
                        "OCI_REVISION": oci_revision or inputs.get("rollback_image_revision") or "f" * 40,
                        # Production maps both from PROD_TINYCLOUD_ADMIN_SECRET: one shared value.
                        "QUOTA_ADMIN_SECRET": canary, "QUOTA_BILLING_ADMIN_SECRET": canary,
                        # Production maps both from PROD_TINYCLOUD_QUOTA_URL: billing's base URL.
                        "QUOTA_BILLING_URL": BILLING_URL, "PHALA_ENV_TINYCLOUD_QUOTA_URL": BILLING_URL, "TEST_RELEASES": json.dumps(releases),
                        "TEST_ORDER": json.dumps(order or ORDER)})
            if running: env["RUNNING_REVISION"] = running
            if missing_billing: env.pop("QUOTA_BILLING_ADMIN_SECRET")
            context = {"github.event_name": event, "github.ref": ref, "job.success": True,
                       **{"inputs." + key: (value == "true" if value in ("true", "false") else value) for key, value in inputs.items()}}
            logs = ""
            names = ["Validate image version against Cargo.toml", "Preflight quota authority", "Validate and pin deployment image",
                     "Preflight sealed runtime configuration", "Prepare allowed_envs synchronization", "Deploy to Phala Cloud",
                     "Verify deployed version", "Verify deployed ingress health", "Restore storage quota overrides",
                     "Verify deployed Policy/v3 routes", "Report unverified storage overrides"]
            names.sort(key=lambda name: SOURCE.index("      - name: " + name + "\n"))
            for name in names:
                script = shell_for_step(name)
                selected = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
                context.update({"steps.pin.outputs." + key: value for key, value in selected.items()})
                context["steps.deploy.outputs.cvm_mutation_attempted"] = selected.get("cvm_mutation_attempted", "")
                if not step_enabled(name, context):
                    if name == "Restore storage quota overrides": context["steps.quotas.outcome"] = "skipped"
                    continue
                env.update({"EXPECTED": selected.get("version", inputs["image_version"]), "IMAGE_REVISION": selected.get("revision", REVISION)})
                result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-c", script], cwd=root, env=env, capture_output=True, text=True)
                logs += result.stdout + result.stderr
                if name == "Restore storage quota overrides": context["steps.quotas.outcome"] = "success" if result.returncode == 0 else "failure"
                if result.returncode != 0: context["job.success"] = False
            report = summary.read_text() if summary.exists() else ""
            self.assertNotIn(canary, logs + report, "Sealed canary leaked")
            self.assertFalse((root / ".phala-prod.env").exists(), "Sealed env was not cleaned")
            return {"success": context["job.success"], "events": json.loads(state.read_text())["events"],
                    "compose": compose_path.read_bytes(), "summary": report, "logs": logs}

    def test_recovery_current_pre_n0_and_reviewed_n0(self):
        for compose in (PRE_N0_TEMPLATE, PRE_N0, N0):
            with self.subTest(n0=compose == N0, template=compose == PRE_N0_TEMPLATE):
                result = self.run_deploy(compose)
                self.assertTrue(result["success"], "Authorized same-image recovery must work")
                self.assertIn("sealed-preflight", result["events"])
                self.assertEqual(result["events"].count("quota-put"), 2)
                self.assertEqual(result["compose"], N0 if compose == N0 else PRE_N0)
                self.assertNotIn("1.20.7", result["logs"] + result["summary"])

    def test_future_digest_gets_preflight_and_general_quota_restore(self):
        result = self.run_deploy(PRE_N0_TEMPLATE, {"deploy_image_digest": "sha256:" + "a" * 64,
             "image_version": "1.20.8", "rollback_image_version": "1.20.8", "rollback_image_revision": "a" * 40})
        self.assertTrue(result["success"])
        self.assertIn("sealed-preflight", result["events"])
        self.assertEqual(result["events"].count("quota-put"), 2)
        self.assertIn(b"@sha256:" + b"a" * 64, result["compose"])

    def test_release_digest_substitutes_only_the_reviewed_n0_node_digest(self):
        # The reviewed template is N0 with its node digest normalized; the
        # source pin is irrelevant, the deployed pin is exactly the release.
        for source in (N0, RELEASE_N0):
            with self.subTest(source_pinned_release=source == RELEASE_N0):
                result = self.run_deploy(source, RELEASE)
                self.assertTrue(result["success"], "Released digest must deploy the reviewed N0 template")
                self.assertEqual(result["compose"], RELEASE_N0)
                self.assertIn("sealed-preflight", result["events"])
                self.assertEqual(result["events"].count("quota-put"), 2)
                self.assertIn("1.21.0-dstack", result["summary"])
                self.assertIn(RELEASE_REVISION, result["summary"])

    def test_n0_release_requires_truthful_release_labels(self):
        for name, releases in (("untagged", {}), ("tag elsewhere", {"1.21.0": ("d" * 40, "1.21.0")}),
                               ("crate disagrees", {"1.21.0": (RELEASE_REVISION, "1.20.7")})):
            with self.subTest(name):
                result = self.run_deploy(N0, RELEASE, releases=releases)
                self.assertFalse(result["success"])
                self.assertNotIn("sealed-preflight", result["events"])
                self.assertNotIn("cvm-deploy", result["events"])
                self.assertEqual(result["compose"], N0)
        with self.subTest("build path, not a recorded digest"):
            result = self.run_deploy(N0, {"deploy_image_digest": "", "image_version": "1.20.7", "rollback_image_version": "",
                                          "rollback_image_revision": ""}, build_digest=RELEASE_DIGEST,
                                     releases={"1.20.7": ("f" * 40, "1.20.7")})
            self.assertFalse(result["success"])
            self.assertNotIn("cvm-deploy", result["events"])
            self.assertEqual(result["compose"], N0)

    def test_release_must_descend_from_the_running_revision(self):
        digest = lambda ch: "sha256:" + ch * 64
        def release(version, revision, ch):
            return ({"deploy_image_digest": digest(ch), "image_version": version, "rollback_image_version": version,
                     "rollback_image_revision": revision}, {version: (revision, version)})
        for name, version, revision, ch, running, ok in (
                ("1.21.0 over running 1.20.6", "1.21.0", RELEASE_REVISION, "b", REVISION, True),
                ("1.20.5 downgrade", "1.20.5", OLD_REVISION, "d", REVISION, False),
                ("1.0.0 downgrade", "1.0.0", ANCIENT_REVISION, "e", REVISION, False),
                ("same revision as running", "1.21.0", RELEASE_REVISION, "b", RELEASE_REVISION, False),
                ("running revision unknown", "1.21.0", RELEASE_REVISION, "b", "", False)):
            with self.subTest(name):
                changes, releases = release(version, revision, ch)
                result = self.run_deploy(N0, changes, releases=releases, running=running)
                self.assertEqual(result["success"], ok)
                if not ok:
                    self.assertNotIn("cvm-deploy", result["events"])
                    self.assertEqual(result["compose"], N0)

    def test_same_image_recovery_refuses_an_older_image_than_running(self):
        for compose in (PRE_N0_TEMPLATE, N0):
            with self.subTest(n0=compose == N0):
                result = self.run_deploy(compose, running=RELEASE_REVISION)
                self.assertFalse(result["success"])
                self.assertNotIn("cvm-deploy", result["events"])
                self.assertEqual(result["compose"], compose)
        with self.subTest("explicit rollback is exempt"):
            result = self.run_deploy(N0, {"rollback_pre_n0": "true", "rollback_privacy_mode": "keep-json-file"},
                                     approved_privacy="keep-json-file", running=RELEASE_REVISION)
            self.assertTrue(result["success"])

    def test_n0_template_drift_refuses_release_digest(self):
        node_line = b"    image: ghcr.io/tinycloudlabs/tinycloud-node@" + DIGEST.encode() + b"\n"
        for name, compose in (("profile", N0.replace(b":-errors_slow}", b":-all_requests}")),
                              ("ingress", N0.replace(b"63c1c44e2ded5b73a5f174807b91ca677826974df0f9ab3045f6ec87865a5744", b"e" * 64)),
                              ("approved pre-cap bytes", N0.replace(b"CLIENT_MAX_BODY_SIZE=95m", b"CLIENT_MAX_BODY_SIZE=32m")),
                              ("crlf", N0.replace(b"\n", b"\r\n")),
                              ("duplicate node", N0.replace(node_line, node_line * 2)),
                              ("quoted node", N0.replace(b"@" + DIGEST.encode(), b"@" + DIGEST.encode() + b"'").replace(
                                  b"image: ghcr.io/tinycloudlabs/tinycloud-node@", b"image: 'ghcr.io/tinycloudlabs/tinycloud-node@"))):
            with self.subTest(name):
                self.assertNotEqual(compose, N0)
                result = self.run_deploy(compose, RELEASE)
                self.assertFalse(result["success"])
                self.assertNotIn("cvm-deploy", result["events"])
                self.assertEqual(result["compose"], compose)

    def test_explicit_rollback_privacy_variants(self):
        for mode, expected in (("keep-json-file", PRE_N0), ("stop-future-local-logs", STOP_LOGS)):
            with self.subTest(mode=mode):
                result = self.run_deploy(N0, {"rollback_pre_n0": "true", "rollback_privacy_mode": mode}, approved_privacy=mode)
                self.assertTrue(result["success"])
                self.assertEqual(result["compose"], expected)
                self.assertEqual(result["events"].count("quota-put"), 2)
                self.assertIn(mode, result["summary"])

    def test_missing_authorization_never_reaches_any_mutation(self):
        for compose, changes, mode in ((PRE_N0_TEMPLATE, {}, ""), (N0, {}, ""),
             (N0, {"rollback_pre_n0": "true", "rollback_privacy_mode": "keep-json-file"}, "keep-json-file"),
             (PRE_N0_TEMPLATE, {"deploy_image_digest": "sha256:" + "a" * 64, "image_version": "1.20.8",
                        "rollback_image_version": "1.20.8", "rollback_image_revision": "a" * 40}, "")):
            result = self.run_deploy(compose, {**changes, "authorize_quota_values": "false"}, approved_privacy=mode)
            self.assertFalse(result["success"])
            self.assertEqual(result["events"], [])
            self.assertEqual(result["compose"], compose)

    def test_wrong_hash_and_artifact_paths_refuse_before_mutation(self):
        wrong = N0.replace(b":-errors_slow}", b":-all_requests}")
        self.assertFalse(self.run_deploy(wrong)["success"])
        for error in ("drift", "missing", "symlink", "stop-drift", "root-symlink"):
            result = self.run_deploy(N0, {"rollback_pre_n0": "true", "rollback_privacy_mode": "stop-future-local-logs"},
                                     artifact_error=error, approved_privacy="stop-future-local-logs")
            self.assertFalse(result["success"])
            self.assertNotIn("cvm-deploy", result["events"])
            self.assertEqual(result["compose"], N0)

    def test_rollback_privacy_is_explicit_approved_and_exclusive(self):
        for changes, approval in (({"rollback_pre_n0": "true"}, ""),
             ({"rollback_pre_n0": "true", "rollback_privacy_mode": "keep-json-file"}, ""),
             ({"rollback_pre_n0": "true", "rollback_privacy_mode": "keep-json-file"}, "stop-future-local-logs"),
             ({"rollback_privacy_mode": "stop-future-local-logs"}, "stop-future-local-logs")):
            result = self.run_deploy(N0, changes, approved_privacy=approval)
            self.assertFalse(result["success"])
            self.assertEqual(result["events"], [])

    def test_missing_authority_or_billing_secret_is_pre_mutation_failure(self):
        for authority in (None, "unknown"):
            result = self.run_deploy(N0, authority=authority)
            self.assertFalse(result["success"])
            self.assertEqual(result["events"], [])
        result = self.run_deploy(N0, missing_billing=True)
        self.assertFalse(result["success"])
        self.assertEqual(result["events"], [])
        self.assertEqual(result["compose"], N0)

    def test_dispatch_main_and_digest_pins_are_required(self):
        for event, ref, changes in (("push", "refs/heads/main", {}), ("workflow_dispatch", "refs/tags/v1.20.6", {}),
                                    ("workflow_dispatch", "refs/heads/main", {"deploy_image_digest": ""})):
            result = self.run_deploy(N0, changes, event=event, ref=ref)
            self.assertFalse(result["success"])
            self.assertEqual(result["events"], [])

    def test_wrong_oci_labels_refuse_before_compose_or_cvm_mutation(self):
        for label, revision in (("1.20.6-dstack-duckdb", None), (None, "f" * 40)):
            result = self.run_deploy(N0, oci_label=label, oci_revision=revision)
            self.assertFalse(result["success"])
            self.assertNotIn("cvm-deploy", result["events"])
            self.assertEqual(result["compose"], N0)

    def test_normal_build_deployment_keeps_preflight_and_general_quota(self):
        result = self.run_deploy(PRE_N0_TEMPLATE, {"deploy_image_digest": "", "image_version": "1.20.7",
                                        "rollback_image_version": "", "rollback_image_revision": ""},
                                 build_digest="sha256:" + "f" * 64)
        self.assertTrue(result["success"])
        self.assertIn("sealed-preflight", result["events"])
        self.assertEqual(result["events"].count("quota-put"), 2)

    def test_unreleased_digest_and_captured_rollback_are_not_substitutable(self):
        future = {"deploy_image_digest": "sha256:" + "a" * 64, "image_version": "1.20.8",
                  "rollback_image_version": "1.20.8", "rollback_image_revision": "a" * 40}
        rollback = {"rollback_pre_n0": "true", "rollback_privacy_mode": "keep-json-file"}
        for changes, mode in ((future, ""), ({**future, **rollback}, "keep-json-file"), ({**RELEASE, **rollback}, "keep-json-file")):
            result = self.run_deploy(N0, changes, approved_privacy=mode)
            self.assertFalse(result["success"])
            self.assertNotIn("cvm-deploy", result["events"])
            self.assertEqual(result["compose"], N0)
        result = self.run_deploy(N0, {"deploy_image_digest": "", "image_version": "1.20.7",
                                      "rollback_image_version": "", "rollback_image_revision": ""},
                                 build_digest="sha256:" + "f" * 64)
        self.assertFalse(result["success"])
        self.assertNotIn("cvm-deploy", result["events"])
        self.assertEqual(result["compose"], N0)

    def test_last_restart_precedes_health_inventory_and_quota(self):
        result = self.run_deploy(N0, {"rollback_pre_n0": "true", "rollback_privacy_mode": "keep-json-file"}, approved_privacy="keep-json-file")
        self.assertTrue(result["success"])
        events = result["events"]
        self.assertLess(events.index("final-restart"), events.index("ingress-health"))
        self.assertLess(events.index("ingress-health"), events.index("quota-inventory"))
        self.assertLess(events.index("quota-inventory"), events.index("quota-put"))
        self.assertLess(events.index("quota-readback"), events.index("policy-probe"))

    def test_partial_restart_or_quota_failure_is_loudly_unverified(self):
        for failure in ("deploy", "sync", "health", "quota"):
            with self.subTest(phase=failure):
                result = self.run_deploy(N0, {"rollback_pre_n0": "true", "rollback_privacy_mode": "keep-json-file"},
                                         fail_at=failure, approved_privacy="keep-json-file")
                self.assertFalse(result["success"])
                self.assertIn("OVERRIDES UNVERIFIED", result["summary"])

    def test_billing_authority_after_restart_is_read_only_and_cold_cache_safe(self):
        result = self.run_deploy(authority="billing")
        self.assertTrue(result["success"])
        self.assertNotIn("quota-put", result["events"])
        self.assertIn("billing-authoritative", result["summary"])

    def test_policy_failure_cannot_skip_already_verified_quota(self):
        result = self.run_deploy(N0, fail_at="policy")
        self.assertFalse(result["success"])
        self.assertEqual(result["events"].count("quota-put"), 2)
        self.assertNotIn("OVERRIDES UNVERIFIED", result["summary"])

    def test_three_shell_blocks_keep_strict_runtime_options(self):
        probe = """
        require_strict() {
          for option in errexit nounset pipefail; do
            case ":${SHELLOPTS}:" in
              *:"${option}":*) ;;
              *) return 89 ;;
            esac
          done
          builtin printf 'strict\\n' >> "$SHELL_PROBE"
        }
        python3() { require_strict; }
        gh() { require_strict; }
        printf() { require_strict || return; builtin printf "$@"; }
        """
        for name in ("Restore storage quota overrides", "Report unverified storage overrides", "Dispatch Write Probe promote watch"):
            with self.subTest(step=name), tempfile.TemporaryDirectory() as directory:
                startup = Path(directory) / "startup"
                startup.write_text(textwrap.dedent(probe))
                trace = Path(directory) / "probe"
                subprocess.run(["bash", "--noprofile", "--norc", "-c", shell_for_step(name)],
                    env={"PATH": "/usr/bin:/bin", "BASH_ENV": str(startup), "SHELL_PROBE": str(trace),
                         "GITHUB_STEP_SUMMARY": str(Path(directory) / "summary"), "IMAGE": "", "GITHUB_REPOSITORY": "synthetic/repository"},
                    capture_output=True, text=True)
                self.assertEqual(trace.read_text().splitlines(), ["strict"])

    def test_documented_recovery_rollback_and_release_commands(self):
        text = (ROOT / "docs/releasing.md").read_text()
        for heading, count, compose in (("### Emergency same-image recovery (12c)", 1, CURRENT),
                                        ("### TC-1302 captured pre-N0 rollback", 2, CURRENT),
                                        ("### Main release with N0 log shipping (one dispatch)", 1, N0)):
            self.assertTrue(heading in text, "Copy-paste recovery contract is missing")
            section = text.split(heading, 1)[1].split("\n### ", 1)[0].split("\n## ", 1)[0]
            commands = re.findall(r"```sh\n(gh workflow run docker.yml.*?)\n```", section, re.S)
            self.assertEqual(len(commands), count)
            for command in commands:
                command = command.replace("<release-dstack-digest>", "b" * 64).replace("<release-commit-sha>", RELEASE_REVISION)
                tokens = shlex.split(command.replace("\\\n", " "))
                self.assertEqual(tokens[:6], ["gh", "workflow", "run", "docker.yml", "-R", "TinyCloudLabs/tinycloud-node"])
                self.assertEqual(tokens[tokens.index("--ref") + 1], "main")
                inputs = dict(tokens[index + 1].split("=", 1) for index, value in enumerate(tokens) if value == "-f")
                mode = inputs.get("rollback_privacy_mode", "")
                result = self.run_deploy(compose, inputs, approved_privacy=mode)
                self.assertTrue(result["success"], "Documented command failed actual input validation")
                inputs.pop("authorize_quota_values")
                denied = self.run_deploy(compose, inputs, missing_authorization=True, approved_privacy=mode)
                self.assertFalse(denied["success"])
                self.assertEqual(denied["events"], [])


if __name__ == "__main__":
    unittest.main(testRunner=unittest.TextTestRunner(resultclass=SafeResult, verbosity=2))

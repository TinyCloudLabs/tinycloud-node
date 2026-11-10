import importlib.util
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("rekey_export", Path(__file__).with_name("export-rekey-manifest.py"))
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class ExportGuards(unittest.TestCase):
    def test_multihost_and_ambiguous_ports_are_refused_before_connecting(self):
        for url in (
            "postgres://localhost:5432,db.prod.example:5432/restored",
            "postgres://127.0.0.1:1,remote/restored",
            "postgres://[::1]:5432,remote:5432/restored",
            "postgres://user,name@localhost:5432/restored",
            "postgres://localhost:not-a-port/restored",
            "postgres://localhost:65536/restored",
            "postgres://127.0.0.2/restored",
            "postgres://localhost/restored?hostaddr=192.0.2.1",
            "postgres://localhost/restored?service=remote",
        ):
            with self.subTest(url=url), mock.patch.object(exporter.subprocess, "run") as connect:
                with self.assertRaises(ValueError):
                    exporter.read_postgres(url, "public")
                connect.assert_not_called()

    def test_nonlocal_live_database_and_override_urls_are_refused_before_connecting(self):
        with mock.patch.object(exporter.subprocess, "run") as connect:
            for url in (
                "postgres://example.invalid/restored",
                "postgres://127.0.0.1/tinycloud-node-production-usw",
                "postgres://127.0.0.1/%74inycloud-node-production-usw",
                "postgres://127.0.0.1/restored?host=example.invalid",
                "postgres:///restored",
            ):
                with self.assertRaises(ValueError):
                    exporter.read_postgres(url, "public")
            connect.assert_not_called()

    def test_schema_injection_is_refused_before_connecting(self):
        with mock.patch.object(exporter.subprocess, "run") as connect:
            with self.assertRaises(ValueError):
                exporter.read_postgres("postgres://127.0.0.1/restored", 'public"; COMMIT;')
            connect.assert_not_called()

    def test_duplicate_identities_are_not_collapsed(self):
        row = ("network", "urn:tinycloud:encryption:did:key:z6Mk:default", None, 1, "11" * 32)
        with self.assertRaises(ValueError):
            exporter.canonical_rows([row, row])


if __name__ == "__main__":
    unittest.main()

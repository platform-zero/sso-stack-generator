#!/usr/bin/env python3
"""Isolated acceptance and rejection cases for the release source gate."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import hashlib
import subprocess

SCRIPT = Path(__file__).with_name("verify-podman-source.py")
spec = importlib.util.spec_from_file_location("verify_podman_source", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def save(path, data):
    path.write_text(json.dumps(data, sort_keys=True))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SourceGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.site = root / "site"
        self.bundle = root / "bundle"
        self.site.mkdir()
        self.bundle.mkdir()
        self.module = {"id": "example", "remote": "https://example.invalid/example.git", "commit": "b" * 40, "dirty": False}
        save(self.site / "manifest.json", {"stackConfig": "config.yaml", "modules": ["example"]})
        (self.site / "config.yaml").write_text("example: true\n")
        save(self.site / ".webservices-generator.json", {"generatorCommit": "a" * 40})
        save(self.site / "modules.json", {"modules": [{"name": "example", "git": self.module["remote"], "commit": self.module["commit"]}]})
        save(self.site / "module-lock.v2.json", {"modules": [{"id": "example", "git": self.module["remote"], "commit": self.module["commit"]}]})
        save(self.bundle / "stack.ir.json", {"modules": [{key: value for key, value in self.module.items() if key != "dirty"}]})
        subprocess.run(["git", "-C", str(self.site), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.site), "add", "."], check=True)
        self.commit("lock snapshot")
        pin = json.loads((self.site / ".webservices-generator.json").read_text())
        pin["moduleManifestCommit"] = self.head()
        save(self.site / ".webservices-generator.json", pin)
        subprocess.run(["git", "-C", str(self.site), "add", "."], check=True)
        self.commit("pin lock snapshot")
        self.provenance = {
            "schemaVersion": 1, "generatorCommit": "a" * 40, "generatorDirty": False,
            "siteCommit": self.head(), "siteDirty": False,
            "manifestSha256": digest(self.site / "manifest.json"), "stackConfigSha256": digest(self.site / "config.yaml"),
            "modules": [self.module.copy()],
        }
        self.store()

    def head(self):
        return subprocess.check_output(["git", "-C", str(self.site), "rev-parse", "HEAD"], text=True).strip()

    def commit(self, message):
        subprocess.run(["git", "-C", str(self.site), "-c", "user.name=GateTest",
                        "-c", "user.email=test@example.invalid", "commit", "-qm", message], check=True)

    def store(self):
        save(self.bundle / "source-provenance.json", self.provenance)
        save(self.bundle / "bundle.json", {"backend": "podman", "irSha256": digest(self.bundle / "stack.ir.json"),
             "sourceProvenanceSha256": digest(self.bundle / "source-provenance.json")})

    def test_clean_exact_pins_pass(self):
        self.assertEqual(gate.verify(self.bundle, self.site), 1)

    def test_checkout_mutation_or_wrong_revision_fails(self):
        (self.site / "untracked.txt").write_text("new source\n")
        with self.assertRaisesRegex(ValueError, "site checkout is dirty"):
            gate.verify(self.bundle, self.site)
        (self.site / "untracked.txt").unlink()
        self.provenance["siteCommit"] = "c" * 40
        self.store()
        with self.assertRaisesRegex(ValueError, "site checkout does not match"):
            gate.verify(self.bundle, self.site)

    def test_lock_must_match_immutable_manifest_commit(self):
        lock = self.site / "module-lock.v2.json"
        lock.write_text(lock.read_text() + "\n")
        subprocess.run(["git", "-C", str(self.site), "add", "module-lock.v2.json"], check=True)
        self.commit("change lock without updating pinned manifest")
        self.provenance["siteCommit"] = self.head()
        self.store()
        with self.assertRaisesRegex(ValueError, "immutable pinned module manifest"):
            gate.verify(self.bundle, self.site)

    def test_dirty_and_missing_revisions_fail(self):
        for field in ("generatorDirty", "siteDirty"):
            self.provenance[field] = True
            self.store()
            with self.assertRaisesRegex(ValueError, "dirty"):
                gate.verify(self.bundle, self.site)
            self.provenance[field] = False
        self.provenance["modules"][0]["dirty"] = True
        self.store()
        with self.assertRaisesRegex(ValueError, "dirty"):
            gate.verify(self.bundle, self.site)
        self.provenance["modules"][0]["dirty"] = False
        self.provenance["siteCommit"] = None
        self.store()
        with self.assertRaisesRegex(ValueError, "site commit"):
            gate.verify(self.bundle, self.site)

    def test_tampered_bundle_or_mismatched_pin_fails(self):
        (self.bundle / "stack.ir.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "runtime IR hash"):
            gate.verify(self.bundle, self.site)
        save(self.bundle / "stack.ir.json", {"modules": [{key: value for key, value in self.module.items() if key != "dirty"}]})
        self.store()
        save(self.site / "module-lock.v2.json", {"modules": [{"id": "example", "git": self.module["remote"], "commit": "d" * 40}]})
        with self.assertRaisesRegex(ValueError, "site locks"):
            gate.verify(self.bundle, self.site)


if __name__ == "__main__":
    unittest.main()

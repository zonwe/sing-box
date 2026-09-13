"""Exercise shell failure handling in temporary directories with service stubs."""

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("TEST_BASH") or (
    r"C:\Program Files\Git\bin\bash.exe" if os.name == "nt" else shutil.which("bash")
)
JQ = os.environ.get("TEST_JQ") or shutil.which("jq")


def functions(path, *names):
    source = (ROOT / path).read_text(encoding="utf-8")
    return "\n".join(
        re.search(r"(?ms)^" + re.escape(name) + r"\(\) \{\n.*?^\}", source).group()
        for name in names
    )


@unittest.skipUnless(BASH and JQ, "Bash and jq are required for isolated shell tests")
class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sing-box-test-")
        self.root = Path(self.temp.name).resolve()
        self.assertEqual(self.root.parent, Path(tempfile.gettempdir()).resolve())
        self.conf = self.root / "conf"
        self.conf.mkdir()
        self.original = '{"inbounds":[{"tag":"old"}]}\n'
        (self.conf / "old.json").write_text(self.original, encoding="utf-8")
        (self.root / "config.json").write_text("{}\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def run_shell(self, script, **variables):
        env = os.environ.copy()
        env.update({
            "is_core_dir": self.root.as_posix(),
            "is_conf_dir": self.conf.as_posix(),
            "is_config_json": (self.root / "config.json").as_posix(),
            "is_audit_config": (self.root / "config.json").as_posix(),
            "is_core_bin": "fake_core",
        })
        env.update(variables)
        prelude = '''
err() { printf '%s\n' "$*" >&2; return 1; }
msg() { :; }
_green() { :; }
manage() { printf 'unexpected service operation\n' >&2; return 99; }
fake_core() {
    [[ $FAIL_CHECK != 1 ]] || return 1
    [[ -f $5/old.json && -f $5/new.json ]] && return 1
    jq empty "$3" || return 1
    local file
    for file in "$5"/*.json; do
        [[ -f $file ]] || continue
        jq empty "$file" || return 1
    done
    return 0
}
'''
        prelude += "\njq() { " + shlex.quote(Path(JQ).as_posix()) + ' "$@"; }\n'
        return subprocess.run(
            [BASH, "--noprofile", "--norc"], input=prelude + script,
            text=True, encoding="utf-8", capture_output=True, env=env, timeout=15,
        )

    def test_generation_failure_preserves_old_configuration(self):
        script = functions("src/core.sh", "create") + '''
get() { :; }
jq() { return 1; }
is_config_file=old.json
is_protocol=trojan
port=1443
json_str='users:[]'
create server Trojan
'''
        result = self.run_shell(script)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.conf / "old.json").read_text(), self.original)
        self.assertFalse((self.conf / "Trojan-1443.json").exists())

    def test_invalid_configuration_preserves_old_file(self):
        for content, reject in (("invalid-json", "0"), ('{"inbounds":[]}', "1")):
            with self.subTest(content=content):
                script = functions("src/core.sh", "write_config") + '\nwrite_config "$is_conf_dir/old.json" "$CONTENT"\n'
                result = self.run_shell(script, CONTENT=content, FAIL_CHECK=reject)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.conf / "old.json").read_text(), self.original)
                self.assertEqual(list(self.root.glob(".config.*")), [])

    def test_valid_replacement_is_backed_up_and_renames_validate_without_old_inbound(self):
        script = functions("src/core.sh", "write_config") + '\nwrite_config "$is_conf_dir/new.json" "$CONTENT" "$is_conf_dir/old.json"\n'
        content = '{"inbounds":[{"tag":"new"}]}'
        result = self.run_shell(script, CONTENT=content)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.conf / "new.json").read_text()), json.loads(content))
        self.assertEqual((self.root / "backups" / "old.json").read_text(), self.original)
        self.assertEqual(list(self.root.glob(".config.*")), [])

    def test_export_failure_preserves_report_and_success_replaces_it(self):
        output = self.root / "report with spaces.json"
        script = functions("src/audit.sh", "audit_export") + '''
audit_config_get() { printf 'synthetic\n'; }
_wget() {
    while [[ $# -gt 0 ]]; do
        if [[ $1 == -O ]]; then
            printf '{"exported":true}\n' >"$2"
            break
        fi
        shift
    done
    return "$DOWNLOAD_STATUS"
}
audit_export json 7d "$OUTPUT"
'''
        for status in ("1", "0"):
            with self.subTest(status=status):
                output.write_text("original report", encoding="utf-8")
                result = self.run_shell(script, OUTPUT=output.as_posix(), DOWNLOAD_STATUS=status)
                if status == "1":
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(output.read_text(), "original report")
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(json.loads(output.read_text())["exported"])
                self.assertEqual(list(self.root.glob("*.tmp.*")), [])


if __name__ == "__main__":
    unittest.main()

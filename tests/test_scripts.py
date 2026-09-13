"""Exercise shell failure handling in temporary directories with service stubs."""

import json
import io
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import tarfile
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
        if os.name == "nt":
            # GNU tar interprets C:/... as a remote archive; use Git Bash paths.
            for key, value in env.items():
                if key in variables or key.startswith("is_"):
                    if re.match(r"^[A-Za-z]:[/\\]", value):
                        env[key] = "/" + value[0].lower() + value[2:].replace("\\", "/")
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

    def test_bulk_repair_validates_each_candidate_and_checks_all_before_restart(self):
        script = functions("src/core.sh", "write_config", "main") + '''
fake_core() {
    local file
    if [[ $# == 3 ]]; then
        jq -e '.repaired == true' "$3" >/dev/null
    else
        for file in "$5"/*.json; do
            jq -e '.repaired == true' "$file" >/dev/null || return 1
        done
    fi
}
change() {
    local content='{"repaired":true}'
    [[ $FAIL_REPAIR == 1 && $1 == second.json ]] && content='{"repaired":false}'
    write_config "$is_conf_dir/$1" "$content"
}
manage() { printf 'restart\n' >"$is_core_dir/service.log"; }
main fix-all
result=$?
wait
exit "$result"
'''
        for fail in ("0", "1"):
            with self.subTest(fail=fail):
                for name in ("old.json", "second.json"):
                    (self.conf / name).write_text('{"repaired":false}')
                log = self.root / "service.log"
                if log.exists():
                    log.unlink()
                result = self.run_shell(script, FAIL_REPAIR=fail)
                if fail == "0":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(log.exists())
                    self.assertTrue(json.loads((self.conf / "second.json").read_text())["repaired"])
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(log.exists())
                    self.assertFalse(json.loads((self.conf / "second.json").read_text())["repaired"])

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

    def test_update_preserves_stopped_service_and_rolls_back_failed_restart(self):
        for module in ("src/download.sh", "install.sh"):
            for directory in (False, True):
                for running in ("0", "1"):
                    with self.subTest(module=module, directory=directory, running=running):
                        case = self.root / (module.replace("/", "-") + str(directory) + running)
                        case.mkdir()
                        target = case / "installed"
                        candidate = case / "candidate"
                        if directory:
                            target.mkdir()
                            candidate.mkdir()
                        current_file = target / "value" if directory else target
                        new_file = candidate / "value" if directory else candidate
                        current_file.write_text("old")
                        new_file.write_text("new")
                        log = case / "restart.log"
                        script = functions(module, "install_update") + '''
update_service_running() { [[ $RUNNING == 1 ]]; }
update_service_restart() {
    cat "$CURRENT_FILE" >>"$RESTART_LOG"
    [[ $(cat "$CURRENT_FILE") == old ]]
}
install_update "$CANDIDATE" "$TARGET" synthetic-service
'''
                        result = self.run_shell(script, CANDIDATE=candidate.as_posix(), TARGET=target.as_posix(),
                                                CURRENT_FILE=current_file.as_posix(), RESTART_LOG=log.as_posix(), RUNNING=running)
                        if running == "1":
                            self.assertNotEqual(result.returncode, 0)
                            self.assertEqual(current_file.read_text(), "old")
                            self.assertEqual(log.read_text(), "newold")
                        else:
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(current_file.read_text(), "new")
                            self.assertFalse(log.exists())
                        self.assertEqual(list(case.glob(".update.*")), [])

    def test_failed_directory_switch_restores_previous_tree(self):
        target = self.root / "installed"
        target.mkdir()
        (target / "value").write_text("old")
        candidate = self.root / "candidate"
        candidate.mkdir()
        (candidate / "value").write_text("new")
        script = functions("src/download.sh", "install_update") + '''
update_service_running() { return 1; }
mv() {
    [[ $* == *'/new '* ]] && return 1
    command mv "$@"
}
install_update "$CANDIDATE" "$TARGET" synthetic-service
'''
        result = self.run_shell(script, CANDIDATE=candidate.as_posix(), TARGET=target.as_posix())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((target / "value").read_text(), "old")
        self.assertEqual(list(self.root.glob(".update.*")), [])

    def test_archive_rejects_corruption_traversal_and_links(self):
        for kind in ("valid", "corrupt", "traversal", "symlink"):
            archive = self.root / (kind + ".tar.gz")
            if kind == "corrupt":
                archive.write_bytes(b"not an archive")
            else:
                with tarfile.open(archive, "w:gz") as output:
                    item = tarfile.TarInfo("../outside" if kind == "traversal" else "file")
                    if kind == "symlink":
                        item.type = tarfile.SYMTYPE
                        item.linkname = "../outside"
                        output.addfile(item)
                    else:
                        item.size = 1
                        output.addfile(item, io.BytesIO(b"x"))
            for module in ("src/download.sh", "install.sh"):
                with self.subTest(kind=kind, module=module):
                    result = self.run_shell(functions(module, "validate_archive") + '\nvalidate_archive "$ARCHIVE"\n', ARCHIVE=archive.as_posix())
                    self.assertEqual(result.returncode == 0, kind == "valid", result.stderr)

    def test_download_rejects_invalid_digest_before_replacing_scripts(self):
        archive = self.root / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name in ("sing-box.sh", "src/core.sh", "src/init.sh"):
                content = b"#!/bin/bash\ntrue\n"
                item = tarfile.TarInfo(name)
                item.size = len(content)
                output.addfile(item, io.BytesIO(content))
        target = self.root / "sh"
        target.mkdir()
        (target / "original").write_text("old")
        names = ("download", "validate_archive", "validate_scripts", "install_update")
        script = functions("src/download.sh", *names) + '''
warn() { :; }
update_service_running() { return 1; }
_wget() {
    local url output
    for arg in "$@"; do [[ $arg == https:* ]] && url=$arg; done
    while [[ $# -gt 0 ]]; do
        if [[ $1 == -O ]]; then output=$2; break; fi
        shift
    done
    if [[ $url == *.sha256 ]]; then
        if [[ $DIGEST == invalid ]]; then
            printf '%064d  code.tar.gz\n' 0 >"$output"
        else
            sha256sum "$ARCHIVE" >"$output"
        fi
    else
        cp "$ARCHIVE" "$output"
    fi
}
download sh v1.18
'''
        for digest in ("invalid", "valid"):
            result = self.run_shell(script, ARCHIVE=archive.as_posix(), DIGEST=digest,
                                    is_sh_dir=target.as_posix(), is_sh_repo="synthetic/repository", is_audit_name="synthetic-audit")
            if digest == "invalid":
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((target / "original").read_text(), "old")
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((target / "sing-box.sh").exists())


if __name__ == "__main__":
    unittest.main()

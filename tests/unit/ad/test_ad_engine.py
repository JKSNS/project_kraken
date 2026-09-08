"""Unit tests for the Kraken Attack/Defense engine.

Tests cover:
- Module imports for all A/D subpackages
- Config dataclass creation and load_config YAML parsing
- GameEngine instantiation with mocked subsystems
- Offense module classes (ExploitManager, ExploitThrower, FlagSubmitter, VulnScanner)
- Defense module classes (TrafficAnalyzer, ServicePatcher, SLAMonitor, DynamicFirewall)
- Infra module classes (TeamManager, NetworkManager, ScoreboardTracker, ServiceDockerManager)
- TickStats dataclass behavior
- GameConfig property methods
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# 1) Import tests -- verify every A/D module can be imported
# ---------------------------------------------------------------------------


class TestImports:
    """Verify all A/D modules import without errors."""

    def test_import_ad_package(self):
        import kraken.ad

        assert hasattr(kraken.ad, "__version__")

    def test_import_config(self):
        from kraken.ad.config import GameConfig, load_config

        assert GameConfig is not None
        assert load_config is not None

    def test_import_engine(self):
        from kraken.ad.engine import GameEngine, TickStats

        assert GameEngine is not None
        assert TickStats is not None

    def test_import_cli(self):
        from kraken.ad.cli import main

        assert callable(main)

    def test_import_offense_package(self):
        from kraken.ad.offense import ExploitManager

        assert ExploitManager is not None

    def test_import_exploit_manager(self):
        from kraken.ad.offense.exploit_manager import ExploitManager

        assert ExploitManager is not None

    def test_import_thrower(self):
        from kraken.ad.offense.thrower import ExploitThrower

        assert ExploitThrower is not None

    def test_import_flag_submitter(self):
        from kraken.ad.offense.flag_submitter import FlagStatus, FlagSubmitter

        assert FlagSubmitter is not None
        assert FlagStatus.ACCEPTED.value == "accepted"

    def test_import_vuln_scanner(self):
        from kraken.ad.offense.vuln_scanner import Vulnerability, VulnScanner

        assert VulnScanner is not None
        assert Vulnerability is not None

    def test_import_defense_package(self):
        from kraken.ad.defense import TrafficAnalyzer

        assert TrafficAnalyzer is not None

    def test_import_traffic_analyzer(self):
        from kraken.ad.defense.traffic_analyzer import TrafficAnalyzer

        assert TrafficAnalyzer is not None

    def test_import_patcher(self):
        from kraken.ad.defense.patcher import PatchResult, ServicePatcher

        assert ServicePatcher is not None
        assert PatchResult is not None

    def test_import_sla_monitor(self):
        from kraken.ad.defense.sla_monitor import SLAMonitor

        assert SLAMonitor is not None

    def test_import_firewall(self):
        from kraken.ad.defense.firewall import DynamicFirewall, FirewallRule

        assert DynamicFirewall is not None
        assert FirewallRule is not None

    def test_import_infra_package(self):
        from kraken.ad.infra import TeamManager

        assert TeamManager is not None

    def test_import_team_manager(self):
        from kraken.ad.infra.team_manager import Team, TeamManager

        assert TeamManager is not None
        assert Team is not None

    def test_import_network(self):
        from kraken.ad.infra.network import NetworkManager

        assert NetworkManager is not None

    def test_import_scoreboard(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker, TeamScore

        assert ScoreboardTracker is not None
        assert TeamScore is not None

    def test_import_docker_manager(self):
        from kraken.ad.infra.docker_manager import ContainerInfo, ServiceDockerManager

        assert ServiceDockerManager is not None
        assert ContainerInfo is not None


# ---------------------------------------------------------------------------
# 2) Config tests
# ---------------------------------------------------------------------------


class TestGameConfig:
    """Test GameConfig dataclass and YAML loading."""

    def test_default_config(self):
        from kraken.ad.config import GameConfig

        cfg = GameConfig()
        assert cfg.tick_duration == 120
        assert cfg.flag_lifetime == 5
        assert cfg.max_concurrent_exploits == 50
        assert cfg.submit_flags is True
        assert cfg.auto_patch is False
        assert cfg.services == []

    def test_config_flag_regex(self):
        from kraken.ad.config import GameConfig

        cfg = GameConfig()
        regex = cfg.flag_regex
        assert isinstance(regex, re.Pattern)
        # Default format: [A-Z0-9]{31}=
        assert regex.search("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

    def test_config_our_team_id(self):
        from kraken.ad.config import GameConfig, NetworkConfig

        cfg = GameConfig(network=NetworkConfig(our_team_id=7))
        assert cfg.our_team_id == 7

    def test_config_team_count(self):
        from kraken.ad.config import GameConfig, NetworkConfig

        cfg = GameConfig(network=NetworkConfig(team_count=30))
        assert cfg.team_count == 30

    def test_config_service_names(self):
        from kraken.ad.config import GameConfig, ServiceConfig

        cfg = GameConfig(
            services=[
                ServiceConfig(name="vuln1", port=1337),
                ServiceConfig(name="vuln2", port=1338),
            ]
        )
        assert cfg.service_names() == ["vuln1", "vuln2"]

    def test_config_get_service(self):
        from kraken.ad.config import GameConfig, ServiceConfig

        svc = ServiceConfig(name="vuln1", port=1337)
        cfg = GameConfig(services=[svc])
        assert cfg.get_service("vuln1") is svc
        assert cfg.get_service("nonexistent") is None

    def test_config_ensure_dirs(self):
        from kraken.ad.config import GameConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = GameConfig(
                exploit_dir=os.path.join(tmpdir, "exploits"),
                patch_dir=os.path.join(tmpdir, "patches"),
                pcap_dir=os.path.join(tmpdir, "pcaps"),
                backup_dir=os.path.join(tmpdir, "backups"),
                log_dir=os.path.join(tmpdir, "logs"),
            )
            cfg.ensure_dirs()
            assert Path(cfg.exploit_dir).is_dir()
            assert Path(cfg.patch_dir).is_dir()
            assert Path(cfg.pcap_dir).is_dir()
            assert Path(cfg.backup_dir).is_dir()
            assert Path(cfg.log_dir).is_dir()

    def test_load_config_from_yaml(self):
        from kraken.ad.config import load_config

        yaml_content = textwrap.dedent("""\
            game:
              tick_duration: 60
              flag_lifetime: 3
              flag_format: 'FLAG[a-z0-9]+'
            network:
              our_team_id: 5
              team_count: 10
              ip_template: "10.{team_id}.0.2"
            scoring:
              scorebot_url: "http://scorebot.local/submit"
              scorebot_token: "abc123"
            services:
              - name: svc1
                port: 9001
                protocol: tcp
              - name: svc2
                port: 9002
                protocol: http
                timeout: 15.0
            exploit_dir: /tmp/test_exploits
            max_concurrent_exploits: 25
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                cfg = load_config(f.name)
                assert cfg.tick_duration == 60
                assert cfg.flag_lifetime == 3
                assert cfg.network.our_team_id == 5
                assert cfg.network.team_count == 10
                assert cfg.scoring.scorebot_url == "http://scorebot.local/submit"
                assert cfg.scoring.scorebot_token == "abc123"
                assert len(cfg.services) == 2
                assert cfg.services[0].name == "svc1"
                assert cfg.services[0].port == 9001
                assert cfg.services[1].protocol == "http"
                assert cfg.services[1].timeout == 15.0
                assert cfg.max_concurrent_exploits == 25
            finally:
                os.unlink(f.name)

    def test_load_config_file_not_found(self):
        from kraken.ad.config import load_config

        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/game.yaml")

    def test_env_var_substitution(self):
        from kraken.ad.config import _substitute_env_vars

        os.environ["KRAKEN_TEST_TOKEN"] = "secret123"
        try:
            result = _substitute_env_vars("token: ${KRAKEN_TEST_TOKEN}")
            assert result == "token: secret123"
        finally:
            del os.environ["KRAKEN_TEST_TOKEN"]

    def test_env_var_substitution_default(self):
        from kraken.ad.config import _substitute_env_vars

        # Ensure the var doesn't exist
        os.environ.pop("KRAKEN_NONEXISTENT_VAR", None)
        result = _substitute_env_vars("token: ${KRAKEN_NONEXISTENT_VAR:-fallback}")
        assert result == "token: fallback"


# ---------------------------------------------------------------------------
# 3) GameEngine instantiation tests (mocked)
# ---------------------------------------------------------------------------


class TestGameEngine:
    """Test GameEngine instantiation and basic methods."""

    def _make_config(self):
        from kraken.ad.config import GameConfig, NetworkConfig, ScoringConfig, ServiceConfig

        return GameConfig(
            tick_duration=10,
            network=NetworkConfig(our_team_id=1, team_count=3),
            scoring=ScoringConfig(scorebot_url="", scorebot_token=""),
            services=[
                ServiceConfig(name="vuln1", port=1337),
            ],
            exploit_dir="/tmp/test_ad_exploits_nonexistent",
            submit_flags=False,
        )

    def test_engine_instantiation(self):
        from kraken.ad.engine import GameEngine

        cfg = self._make_config()
        engine = GameEngine(cfg)
        assert engine.tick_number == 0
        assert engine.running is False
        assert len(engine.tick_history) == 0

    def test_engine_has_subsystems(self):
        from kraken.ad.engine import GameEngine

        cfg = self._make_config()
        engine = GameEngine(cfg)
        assert engine.team_mgr is not None
        assert engine.exploit_mgr is not None
        assert engine.flag_submitter is not None
        assert engine.thrower is not None
        assert engine.traffic_analyzer is not None
        assert engine.patcher is not None
        assert engine.sla_monitor is not None
        assert engine.firewall is not None
        assert engine.scoreboard is not None

    def test_engine_teams_populated(self):
        from kraken.ad.engine import GameEngine

        cfg = self._make_config()
        engine = GameEngine(cfg)
        # 3 teams total (including ours)
        assert len(engine.team_mgr) == 3
        opponents = engine.team_mgr.get_opponents()
        assert 1 not in opponents  # our team excluded
        assert len(opponents) == 2

    def test_engine_get_status(self):
        from kraken.ad.engine import GameEngine

        cfg = self._make_config()
        engine = GameEngine(cfg)
        status = engine.get_status()
        assert status["running"] is False
        assert status["tick_number"] == 0
        assert status["total_flags_captured"] == 0
        assert status["last_tick"] is None

    def test_engine_stop(self):
        from kraken.ad.engine import GameEngine

        cfg = self._make_config()
        engine = GameEngine(cfg)
        engine.running = True
        engine.stop()
        assert engine.running is False

    def test_engine_on_tick_callback(self):
        from kraken.ad.engine import GameEngine

        cfg = self._make_config()
        engine = GameEngine(cfg)
        callback = MagicMock()
        engine.on_tick(callback)
        assert callback in engine._tick_callbacks


class TestTickStats:
    """Test TickStats dataclass."""

    def test_tick_stats_defaults(self):
        from kraken.ad.engine import TickStats

        stats = TickStats(tick_number=1, start_time=100.0)
        assert stats.tick_number == 1
        assert stats.flags_captured == 0
        assert stats.sla_checks_passed == 0
        assert stats.errors == []

    def test_tick_stats_duration(self):
        from kraken.ad.engine import TickStats

        stats = TickStats(tick_number=1, start_time=100.0, end_time=110.5)
        assert stats.duration == pytest.approx(10.5)

    def test_tick_stats_duration_no_end(self):
        from kraken.ad.engine import TickStats

        stats = TickStats(tick_number=1, start_time=100.0)
        assert stats.duration == 0.0


# ---------------------------------------------------------------------------
# 4) Offense module tests
# ---------------------------------------------------------------------------


class TestExploitManager:
    """Test ExploitManager."""

    def test_init(self):
        from kraken.ad.offense.exploit_manager import ExploitManager

        mgr = ExploitManager(exploit_dir="/tmp/test_exploits_nonexistent")
        assert mgr.exploits == {}
        assert mgr.default_timeout == 30.0

    def test_load_exploits_no_dir(self):
        from kraken.ad.offense.exploit_manager import ExploitManager

        mgr = ExploitManager(exploit_dir="/tmp/nonexistent_dir_12345")
        mgr.load_exploits()  # Should not raise
        assert mgr.exploits == {}

    def test_load_exploits_with_scripts(self):
        from kraken.ad.offense.exploit_manager import ExploitManager

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create exploit directory structure
            svc_dir = Path(tmpdir) / "vuln1"
            svc_dir.mkdir()
            (svc_dir / "exploit1.py").write_text("print('flag')")
            (svc_dir / "exploit2.sh").write_text("echo flag")
            (svc_dir / "_helper.py").write_text("# internal")  # Should be skipped
            (svc_dir / "readme.txt").write_text("docs")  # Wrong extension

            mgr = ExploitManager(exploit_dir=tmpdir)
            mgr.load_exploits()
            assert "vuln1" in mgr.exploits
            assert len(mgr.exploits["vuln1"]) == 2  # .py and .sh only

    def test_custom_flag_regex(self):
        from kraken.ad.offense.exploit_manager import ExploitManager

        mgr = ExploitManager(
            exploit_dir="/tmp/test",
            flag_regex=re.compile(r"FLAG\{[a-z0-9]+\}"),
        )
        assert mgr.flag_regex.search("FLAG{abc123}")

    def test_get_best_exploit_no_data(self):
        from kraken.ad.offense.exploit_manager import ExploitManager

        mgr = ExploitManager(exploit_dir="/tmp/test")
        assert mgr.get_best_exploit("vuln1") is None

    def test_get_stats_empty(self):
        from kraken.ad.offense.exploit_manager import ExploitManager

        mgr = ExploitManager(exploit_dir="/tmp/test")
        assert mgr.get_stats() == {}

    def test_remove_exploit_nonexistent(self):
        from kraken.ad.offense.exploit_manager import ExploitManager

        mgr = ExploitManager(exploit_dir="/tmp/test")
        assert mgr.remove_exploit("vuln1", "nope.py") is False


class TestFlagSubmitter:
    """Test FlagSubmitter."""

    def test_init(self):
        from kraken.ad.offense.flag_submitter import FlagSubmitter

        sub = FlagSubmitter(scorebot_url="http://example.com", token="abc")
        assert sub.url == "http://example.com"
        assert sub.token == "abc"
        assert sub.accepted == 0
        assert sub.rejected == 0

    def test_deduplication(self):
        from kraken.ad.offense.flag_submitter import FlagSubmitter

        sub = FlagSubmitter(scorebot_url="", token="")
        sub.submitted.add("FLAG1")

        async def _test():
            await sub.submit("FLAG1")
            # Should not be queued since it's already submitted
            assert sub.queue.qsize() == 0

        asyncio.run(_test())

    def test_get_stats(self):
        from kraken.ad.offense.flag_submitter import FlagSubmitter

        sub = FlagSubmitter(scorebot_url="", token="")
        sub.accepted = 5
        sub.rejected = 2
        sub.duplicate = 3
        stats = sub.get_stats()
        assert stats["accepted"] == 5
        assert stats["rejected"] == 2
        assert stats["duplicate"] == 3

    def test_flag_status_enum(self):
        from kraken.ad.offense.flag_submitter import FlagStatus

        assert FlagStatus.ACCEPTED.value == "accepted"
        assert FlagStatus.REJECTED.value == "rejected"
        assert FlagStatus.DUPLICATE.value == "duplicate"
        assert FlagStatus.EXPIRED.value == "expired"
        assert FlagStatus.OWN_FLAG.value == "own_flag"
        assert FlagStatus.INVALID.value == "invalid"
        assert FlagStatus.ERROR.value == "error"


class TestVulnScanner:
    """Test VulnScanner."""

    def test_init(self):
        from kraken.ad.offense.vuln_scanner import VulnScanner

        scanner = VulnScanner()
        assert scanner.vulnerabilities == []

    def test_scan_source_with_vulnerable_code(self):
        from kraken.ad.offense.vuln_scanner import VulnScanner

        scanner = VulnScanner()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("os.system(user_input)\n")
            f.write('cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n')
            f.flush()
            try:
                vulns = scanner.scan_source(f.name, "test_svc")
                assert len(vulns) > 0
                vuln_types = {v.vuln_type for v in vulns}
                assert "command_injection" in vuln_types
            finally:
                os.unlink(f.name)

    def test_scan_source_nonexistent(self):
        from kraken.ad.offense.vuln_scanner import VulnScanner

        scanner = VulnScanner()
        vulns = scanner.scan_source("/nonexistent/file.py", "svc")
        assert vulns == []

    def test_scan_binary_nonexistent(self):
        from kraken.ad.offense.vuln_scanner import VulnScanner

        scanner = VulnScanner()
        vulns = scanner.scan_binary("/nonexistent/binary", "svc")
        assert vulns == []

    def test_vulnerability_dataclass(self):
        from kraken.ad.offense.vuln_scanner import Vulnerability

        v = Vulnerability(
            service="test",
            vuln_type="buffer_overflow",
            description="gets() used",
            severity="critical",
        )
        assert v.service == "test"
        assert v.verified is False

    def test_get_summary_empty(self):
        from kraken.ad.offense.vuln_scanner import VulnScanner

        scanner = VulnScanner()
        assert scanner.get_summary() == {}

    def test_exploit_hint(self):
        from kraken.ad.offense.vuln_scanner import VulnScanner

        hint = VulnScanner._get_exploit_hint("gets")
        assert "overflow" in hint.lower() or "Overflow" in hint


class TestExploitThrower:
    """Test ExploitThrower."""

    def test_init(self):
        from kraken.ad.infra.team_manager import TeamManager
        from kraken.ad.offense.exploit_manager import ExploitManager
        from kraken.ad.offense.flag_submitter import FlagSubmitter
        from kraken.ad.offense.thrower import ExploitThrower

        em = ExploitManager(exploit_dir="/tmp/test")
        tm = TeamManager()
        fs = FlagSubmitter(scorebot_url="", token="")
        thrower = ExploitThrower(em, tm, fs, max_concurrent=10)
        assert thrower.max_concurrent == 10
        assert thrower.last_exploit_count == 0

    def test_throw_tick_no_opponents(self):
        from kraken.ad.infra.team_manager import TeamManager
        from kraken.ad.offense.exploit_manager import ExploitManager
        from kraken.ad.offense.flag_submitter import FlagSubmitter
        from kraken.ad.offense.thrower import ExploitThrower

        em = ExploitManager(exploit_dir="/tmp/test")
        tm = TeamManager(our_team_id=1)
        # No teams added
        fs = FlagSubmitter(scorebot_url="", token="")
        thrower = ExploitThrower(em, tm, fs)

        async def _test():
            result = await thrower.throw_tick(["vuln1"])
            assert result == {"vuln1": 0}

        asyncio.run(_test())


# ---------------------------------------------------------------------------
# 5) Defense module tests
# ---------------------------------------------------------------------------


class TestTrafficAnalyzer:
    """Test TrafficAnalyzer."""

    def test_init(self):
        from kraken.ad.defense.traffic_analyzer import TrafficAnalyzer

        analyzer = TrafficAnalyzer(interface="eth0", our_team_id=5)
        assert analyzer.interface == "eth0"
        assert analyzer.our_team_id == 5
        assert analyzer.known_patterns == set()
        assert analyzer.attack_log == []

    def test_analyze_pcap_nonexistent(self):
        from kraken.ad.defense.traffic_analyzer import TrafficAnalyzer

        analyzer = TrafficAnalyzer()
        attacks = analyzer.analyze_pcap("/nonexistent/file.pcap")
        assert attacks == []

    def test_has_cyclic_pattern_short_data(self):
        from kraken.ad.defense.traffic_analyzer import TrafficAnalyzer

        assert TrafficAnalyzer._has_cyclic_pattern(b"short") is False

    def test_has_cyclic_pattern_ascii_data(self):
        from kraken.ad.defense.traffic_analyzer import TrafficAnalyzer

        # Create data that looks like a cyclic pattern (all printable ASCII)
        data = b"AAAA" * 100
        result = TrafficAnalyzer._has_cyclic_pattern(data)
        assert result is True  # All ASCII, > 60%

    def test_has_cyclic_pattern_binary_data(self):
        from kraken.ad.defense.traffic_analyzer import TrafficAnalyzer

        # All bytes below 0x20 (non-printable control chars)
        data = bytes(range(0, 32)) * 20
        result = TrafficAnalyzer._has_cyclic_pattern(data)
        # Not ASCII (all control chars), should not match
        assert result is False

    def test_stop_capture_no_proc(self):
        from kraken.ad.defense.traffic_analyzer import TrafficAnalyzer

        analyzer = TrafficAnalyzer()
        analyzer.stop_capture()  # Should not raise


class TestServicePatcher:
    """Test ServicePatcher."""

    def test_init(self):
        from kraken.ad.defense.patcher import ServicePatcher

        patcher = ServicePatcher(service_dir="/tmp/services", backup_dir="/tmp/backups")
        assert patcher.applied_patches == {}

    def test_patch_result(self):
        from kraken.ad.defense.patcher import PatchResult

        r = PatchResult(success=True, message="OK", rollback_available=True)
        assert r.success is True
        assert r.message == "OK"
        assert r.rollback_available is True

    def test_patch_source_nonexistent(self):
        from kraken.ad.defense.patcher import ServicePatcher

        patcher = ServicePatcher()
        result = patcher.patch_source("/nonexistent/file.c", "buffer_overflow")
        assert result.success is False

    def test_patch_binary_nonexistent(self):
        from kraken.ad.defense.patcher import ServicePatcher

        patcher = ServicePatcher()
        result = patcher.patch_binary("/nonexistent/binary", [])
        assert result.success is False

    def test_patch_source_buffer_overflow(self):
        from kraken.ad.defense.patcher import ServicePatcher

        patcher = ServicePatcher()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write('gets(buf);\nstrcpy(dst, src);\nsprintf(buf, "%s", data);\n')
            f.flush()
            try:
                result = patcher.patch_source(f.name, "buffer_overflow")
                assert result.success is True
                content = Path(f.name).read_text()
                assert "fgets" in content
                assert "strncpy" in content
                assert "snprintf" in content
            finally:
                os.unlink(f.name)

    def test_patch_source_format_string(self):
        from kraken.ad.defense.patcher import ServicePatcher

        patcher = ServicePatcher()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write("printf(user_buf);\n")
            f.flush()
            try:
                result = patcher.patch_source(f.name, "format_string")
                assert result.success is True
                content = Path(f.name).read_text()
                assert '"%s"' in content
            finally:
                os.unlink(f.name)

    def test_patch_source_unknown_vuln_type(self):
        from kraken.ad.defense.patcher import ServicePatcher

        patcher = ServicePatcher()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write("int main() { return 0; }\n")
            f.flush()
            try:
                result = patcher.patch_source(f.name, "unknown_vuln_type")
                assert result.success is False
            finally:
                os.unlink(f.name)

    def test_rollback_no_backup(self):
        from kraken.ad.defense.patcher import ServicePatcher

        patcher = ServicePatcher(backup_dir="/tmp/nonexistent_backup_12345")
        result = patcher.rollback("some_service")
        assert result.success is False

    def test_backup_service(self):
        from kraken.ad.defense.patcher import ServicePatcher

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = os.path.join(tmpdir, "backups")
            patcher = ServicePatcher(backup_dir=backup_dir)
            result = patcher.backup_service("test_svc")
            assert Path(backup_dir, "test_svc").is_dir()

    def test_patch_binary_applies_bytes(self):
        from kraken.ad.defense.patcher import ServicePatcher

        patcher = ServicePatcher()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 100)
            f.flush()
            try:
                patches = [
                    {"offset": 10, "original_bytes": b"\x00\x00", "new_bytes": b"\x90\x90"},
                ]
                result = patcher.patch_binary(f.name, patches)
                assert result.success is True
                data = Path(f.name).read_bytes()
                assert data[10:12] == b"\x90\x90"
            finally:
                os.unlink(f.name)

    def test_patch_binary_verification_fails(self):
        from kraken.ad.defense.patcher import ServicePatcher

        patcher = ServicePatcher()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 100)
            f.flush()
            try:
                patches = [
                    {"offset": 10, "original_bytes": b"\xff\xff", "new_bytes": b"\x90\x90"},
                ]
                result = patcher.patch_binary(f.name, patches)
                assert result.success is False
                assert "already been patched" in result.message
            finally:
                os.unlink(f.name)


class TestSLAMonitor:
    """Test SLAMonitor."""

    def test_init(self):
        from kraken.ad.defense.sla_monitor import SLAMonitor

        monitor = SLAMonitor(services={"svc1": {"port": 1337, "protocol": "tcp"}})
        assert "svc1" in monitor.status
        assert monitor.status["svc1"]["up"] is True

    def test_get_uptime_no_checks(self):
        from kraken.ad.defense.sla_monitor import SLAMonitor

        monitor = SLAMonitor(services={"svc1": {"port": 1337}})
        assert monitor.get_uptime("svc1") == 100.0

    def test_record_result(self):
        from kraken.ad.defense.sla_monitor import SLAMonitor

        monitor = SLAMonitor(services={"svc1": {"port": 1337}})
        monitor._record_result("svc1", True)
        monitor._record_result("svc1", True)
        monitor._record_result("svc1", False)
        assert monitor.status["svc1"]["checks_total"] == 3
        assert monitor.status["svc1"]["checks_passed"] == 2
        assert monitor.get_uptime("svc1") == pytest.approx(66.67, abs=0.1)

    def test_is_any_down(self):
        from kraken.ad.defense.sla_monitor import SLAMonitor

        monitor = SLAMonitor(services={"svc1": {"port": 1337}})
        assert monitor.is_any_down() is False
        monitor._record_result("svc1", False)
        assert monitor.is_any_down() is True

    def test_get_critical_services(self):
        from kraken.ad.defense.sla_monitor import SLAMonitor

        monitor = SLAMonitor(services={"svc1": {"port": 1337}})
        for _ in range(5):
            monitor._record_result("svc1", False)
        critical = monitor.get_critical_services(max_failures=3)
        assert "svc1" in critical

    def test_get_status_summary(self):
        from kraken.ad.defense.sla_monitor import SLAMonitor

        monitor = SLAMonitor(services={"svc1": {"port": 1337}})
        summary = monitor.get_status_summary()
        assert "svc1" in summary
        assert "up" in summary["svc1"]
        assert "uptime" in summary["svc1"]

    def test_check_tcp_refused(self):
        from kraken.ad.defense.sla_monitor import SLAMonitor

        monitor = SLAMonitor(services={})

        async def _test():
            # Port 1 is almost always closed
            result = await monitor.check_tcp("127.0.0.1", 1, timeout=1.0)
            assert result is False

        asyncio.run(_test())


class TestDynamicFirewall:
    """Test DynamicFirewall (dry_run mode)."""

    def test_init(self):
        from kraken.ad.defense.firewall import DynamicFirewall

        fw = DynamicFirewall(dry_run=True)
        assert fw.rules == []
        assert fw.dry_run is True

    def test_block_payload_dry_run(self):
        from kraken.ad.defense.firewall import DynamicFirewall

        fw = DynamicFirewall(dry_run=True)
        result = fw.block_payload(b"\x90\x90\x90\x90", 1337, "test block")
        assert result is True
        assert len(fw.rules) == 1
        assert fw.rules[0].rule_type == "block_payload"

    def test_rate_limit_dry_run(self):
        from kraken.ad.defense.firewall import DynamicFirewall

        fw = DynamicFirewall(dry_run=True)
        result = fw.rate_limit("10.0.0.5", 1337, rate="5/s")
        assert result is True
        assert len(fw.rules) == 1
        assert fw.rules[0].rule_type == "rate_limit"

    def test_block_team_dry_run(self):
        from kraken.ad.defense.firewall import DynamicFirewall

        fw = DynamicFirewall(dry_run=True)
        result = fw.block_team("10.0.0.5", 1337)
        assert result is True
        assert len(fw.rules) == 1

    def test_allow_sla_checker_dry_run(self):
        from kraken.ad.defense.firewall import DynamicFirewall

        fw = DynamicFirewall(dry_run=True)
        result = fw.allow_sla_checker(["10.0.0.100", "10.0.0.101"])
        assert result is True
        assert len(fw.rules) == 2

    def test_list_rules(self):
        from kraken.ad.defense.firewall import DynamicFirewall

        fw = DynamicFirewall(dry_run=True)
        fw.block_payload(b"\x90", 1337)
        fw.rate_limit("10.0.0.5", 1337)
        rules = fw.list_rules()
        assert len(rules) == 2

    def test_flush_dry_run(self):
        from kraken.ad.defense.firewall import DynamicFirewall

        fw = DynamicFirewall(dry_run=True)
        fw.block_payload(b"\x90", 1337)
        assert len(fw.rules) == 1
        fw.flush()
        assert len(fw.rules) == 0

    def test_get_stats(self):
        from kraken.ad.defense.firewall import DynamicFirewall

        fw = DynamicFirewall(dry_run=True)
        fw.block_payload(b"\x90", 1337)
        fw.rate_limit("10.0.0.5", 1337)
        stats = fw.get_stats()
        assert stats["total_rules"] == 2
        assert stats["active_rules"] == 2
        assert stats["by_type"]["block_payload"] == 1
        assert stats["by_type"]["rate_limit"] == 1

    def test_firewall_rule_dataclass(self):
        from kraken.ad.defense.firewall import FirewallRule

        rule = FirewallRule(
            rule_type="block_payload",
            description="test",
            iptables_args=["-A", "KRAKEN_AD"],
        )
        assert rule.active is True


# ---------------------------------------------------------------------------
# 6) Infra module tests
# ---------------------------------------------------------------------------


class TestTeamManager:
    """Test TeamManager."""

    def test_init(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager(our_team_id=3)
        assert tm.our_team_id == 3
        assert len(tm) == 0

    def test_add_team(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager()
        team = tm.add_team(1, name="CyberKittens")
        assert team.id == 1
        assert team.name == "CyberKittens"
        assert len(tm) == 1

    def test_remove_team(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager()
        tm.add_team(1)
        assert tm.remove_team(1) is True
        assert tm.remove_team(999) is False

    def test_register_service(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager()
        tm.register_service("vuln1", 1337)
        assert tm.get_port("vuln1") == 1337
        assert tm.get_port("nonexistent") == 0

    def test_get_ip_template(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager(ip_template="10.{team_id}.{service_id}.2")
        tm.add_team(5)
        tm.register_service("vuln1", 1337, service_id=1)
        ip = tm.get_ip(5, "vuln1")
        assert ip == "10.5.1.2"

    def test_get_ip_custom_base(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager()
        tm.add_team(5, ip_base="192.168.1.5")
        ip = tm.get_ip(5)
        assert ip == "192.168.1.5"

    def test_get_opponents(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager(our_team_id=1)
        for i in range(1, 6):
            tm.add_team(i)
        opponents = tm.get_opponents()
        assert 1 not in opponents
        assert len(opponents) == 4

    def test_get_opponents_inactive(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager(our_team_id=1)
        for i in range(1, 4):
            tm.add_team(i)
        tm.set_team_active(3, False)
        opponents = tm.get_opponents()
        assert 3 not in opponents

    def test_get_all_teams(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager()
        tm.add_team(3)
        tm.add_team(1)
        tm.add_team(2)
        teams = tm.get_all_teams()
        assert [t.id for t in teams] == [1, 2, 3]

    def test_get_our_team(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager(our_team_id=1)
        tm.add_team(1, name="Us")
        our = tm.get_our_team()
        assert our.name == "Us"

    def test_load_from_scoreboard(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager()
        data = {
            "teams": [
                {"id": 1, "name": "Team Alpha", "score": 100},
                {"id": 2, "name": "Team Beta", "score": 200},
            ]
        }
        count = tm.load_from_scoreboard(data)
        assert count == 2
        assert tm.get_team(1).name == "Team Alpha"
        assert tm.get_team(2).score == 200

    def test_get_target_list(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager(our_team_id=1, ip_template="10.{team_id}.{service_id}.2")
        tm.add_team(1)
        tm.add_team(2)
        tm.add_team(3)
        tm.register_service("vuln1", 1337, service_id=1)
        targets = tm.get_target_list("vuln1")
        assert len(targets) == 2  # 2 opponents
        assert all(t["port"] == 1337 for t in targets)

    def test_repr(self):
        from kraken.ad.infra.team_manager import TeamManager

        tm = TeamManager(our_team_id=1)
        tm.add_team(1)
        r = repr(tm)
        assert "TeamManager" in r

    def test_team_dataclass(self):
        from kraken.ad.infra.team_manager import Team

        t = Team(id=1, name="TestTeam")
        assert t.active is True
        assert t.score == 0.0
        assert t.services == {}


class TestNetworkManager:
    """Test NetworkManager."""

    def test_init(self):
        from kraken.ad.infra.network import NetworkManager

        nm = NetworkManager(game_interface="eth0", vpn_interface="tun1")
        assert nm.game_interface == "eth0"
        assert nm.vpn_interface == "tun1"

    def test_get_interfaces(self):
        from kraken.ad.infra.network import NetworkManager

        nm = NetworkManager()
        interfaces = nm.get_interfaces()
        # Should return at least lo
        assert isinstance(interfaces, list)

    def test_get_routes(self):
        from kraken.ad.infra.network import NetworkManager

        nm = NetworkManager()
        routes = nm.get_routes()
        assert isinstance(routes, list)


class TestScoreboardTracker:
    """Test ScoreboardTracker."""

    def test_init(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker

        tracker = ScoreboardTracker()
        assert tracker.current_scores == {}
        assert tracker.history == []
        assert tracker.fetch_count == 0

    def test_parse_scoreboard_list_format(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker

        tracker = ScoreboardTracker()
        data = [
            {"id": 1, "name": "Alpha", "score": 300, "attack": 100, "defense": 100, "sla": 100},
            {"id": 2, "name": "Beta", "score": 200, "attack": 50, "defense": 80, "sla": 70},
        ]
        tracker._parse_scoreboard(data)
        assert len(tracker.current_scores) == 2
        assert tracker.current_scores[1].team_name == "Alpha"
        assert tracker.current_scores[1].total_score == 300

    def test_parse_scoreboard_dict_format(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker

        tracker = ScoreboardTracker()
        data = {
            "teams": [
                {"id": 1, "name": "Alpha", "score": 300},
                {"id": 2, "name": "Beta", "score": 200},
            ]
        }
        tracker._parse_scoreboard(data)
        assert len(tracker.current_scores) == 2

    def test_get_top_n(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker

        tracker = ScoreboardTracker()
        tracker._parse_scoreboard(
            [
                {"id": 1, "name": "A", "score": 100},
                {"id": 2, "name": "B", "score": 300},
                {"id": 3, "name": "C", "score": 200},
            ]
        )
        top2 = tracker.get_top_n(2)
        assert len(top2) == 2
        assert top2[0].team_name == "B"  # Highest score first

    def test_get_our_rank(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker

        tracker = ScoreboardTracker()
        tracker._parse_scoreboard(
            [
                {"id": 1, "name": "A", "score": 100, "rank": 2},
                {"id": 2, "name": "B", "score": 300, "rank": 1},
            ]
        )
        assert tracker.get_our_rank(2) == 1
        assert tracker.get_our_rank(999) == -1

    def test_print_standings(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker

        tracker = ScoreboardTracker()
        assert "No scoreboard data" in tracker.print_standings()
        tracker._parse_scoreboard(
            [
                {"id": 1, "name": "Alpha", "score": 100},
            ]
        )
        output = tracker.print_standings()
        assert "Alpha" in output

    def test_load_from_file(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker

        tracker = ScoreboardTracker()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            import json

            json.dump({"teams": [{"id": 1, "name": "Test", "score": 50}]}, f)
            f.flush()
            try:
                result = tracker.load_from_file(f.name)
                assert result is True
                assert len(tracker.current_scores) == 1
            finally:
                os.unlink(f.name)

    def test_save_to_file(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker

        tracker = ScoreboardTracker()
        tracker._parse_scoreboard([{"id": 1, "name": "Test", "score": 50}])
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            try:
                tracker.save_to_file(f.name)
                import json

                data = json.loads(Path(f.name).read_text())
                assert "teams" in data
                assert len(data["teams"]) == 1
            finally:
                os.unlink(f.name)

    def test_get_score_trend(self):
        from kraken.ad.infra.scoreboard import ScoreboardTracker

        tracker = ScoreboardTracker()
        tracker._parse_scoreboard([{"id": 1, "name": "A", "score": 100}])
        tracker._parse_scoreboard([{"id": 1, "name": "A", "score": 200}])
        trend = tracker.get_score_trend(1)
        assert trend == [100.0, 200.0]

    def test_team_score_dataclass(self):
        from kraken.ad.infra.scoreboard import TeamScore

        ts = TeamScore(team_id=1, team_name="Test", total_score=500)
        assert ts.rank == 0
        assert ts.attack_score == 0.0


class TestServiceDockerManager:
    """Test ServiceDockerManager."""

    def test_init(self):
        from kraken.ad.infra.docker_manager import ServiceDockerManager

        dm = ServiceDockerManager(compose_file="docker-compose.yml", use_sudo=True)
        assert dm.compose_file == "docker-compose.yml"
        assert dm.use_sudo is True

    def test_docker_cmd(self):
        from kraken.ad.infra.docker_manager import ServiceDockerManager

        dm = ServiceDockerManager(use_sudo=True)
        cmd = dm._docker_cmd("ps")
        assert cmd == ["sudo", "docker", "ps"]

    def test_docker_cmd_no_sudo(self):
        from kraken.ad.infra.docker_manager import ServiceDockerManager

        dm = ServiceDockerManager(use_sudo=False)
        cmd = dm._docker_cmd("ps", "--all")
        assert cmd == ["docker", "ps", "--all"]

    def test_container_info_dataclass(self):
        from kraken.ad.infra.docker_manager import ContainerInfo

        ci = ContainerInfo(
            container_id="abc123",
            service_name="vuln1",
            image="vuln1:latest",
            status="running",
            port_mapping="0.0.0.0:1337->1337/tcp",
        )
        assert ci.container_id == "abc123"
        assert ci.uptime == ""

    def test_compose_up_no_file(self):
        from kraken.ad.infra.docker_manager import ServiceDockerManager

        dm = ServiceDockerManager()  # No compose file
        assert dm.compose_up() is False

    def test_compose_down_no_file(self):
        from kraken.ad.infra.docker_manager import ServiceDockerManager

        dm = ServiceDockerManager()
        assert dm.compose_down() is False

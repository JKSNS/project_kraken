"""Kraken A/D CLI -- Attack/Defense game management.

Entry point for the ``kraken-ad`` command. Provides subcommands for:
- Starting the game engine
- Managing exploits (add, list, test, remove)
- Managing patches (apply, rollback, list)
- Analyzing traffic (capture, analyze, replay)
- Viewing game status and scoreboard
- Scanning services for vulnerabilities
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

from .config import GameConfig, load_config
from .engine import GameEngine


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_start(args: argparse.Namespace) -> None:
    """Start the game engine."""
    config = load_config(args.config)

    if args.tick:
        config.tick_duration = args.tick

    if args.dry_run:
        config.submit_flags = False

    engine = GameEngine(config)

    print(f"Starting Kraken A/D Engine")
    print(f"  Tick duration: {config.tick_duration}s")
    print(f"  Services: {', '.join(config.service_names()) or 'none'}")
    print(f"  Teams: {config.network.team_count}")
    print(f"  Flag submission: {'enabled' if config.submit_flags else 'DISABLED (dry run)'}")
    print()

    try:
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        print("\nEngine stopped.")


def cmd_exploit(args: argparse.Namespace) -> None:
    """Manage exploits."""
    from .offense.exploit_manager import ExploitManager

    config = _load_config_optional(args)
    exploit_dir = config.exploit_dir if config else args.exploit_dir or "./exploits"

    mgr = ExploitManager(exploit_dir=exploit_dir)
    mgr.load_exploits()

    if args.action == "list":
        if not mgr.exploits:
            print("No exploits loaded.")
            print(f"  Place scripts in: {exploit_dir}/{{service_name}}/{{exploit}}.py")
            return

        for service, scripts in sorted(mgr.exploits.items()):
            print(f"\n  {service}:")
            for script in scripts:
                rate = mgr.success_rate.get(service, {}).get(script.name, 0.0)
                print(f"    - {script.name} (success rate: {rate:.0%})")

    elif args.action == "add":
        if not args.script:
            print("Error: --script required for 'add'")
            sys.exit(1)
        dest = mgr.add_exploit(args.service, args.script)
        print(f"Added exploit: {dest}")

    elif args.action == "test":
        if not args.team:
            print("Error: --team required for 'test'")
            sys.exit(1)

        from .infra.team_manager import TeamManager

        team_mgr = TeamManager(
            ip_template=config.network.ip_template if config else "10.{team_id}.{service_id}.2",
            our_team_id=config.network.our_team_id if config else 1,
        )
        for i in range(1, (config.network.team_count if config else 20) + 1):
            team_mgr.add_team(i)

        if config:
            for svc in config.services:
                team_mgr.register_service(svc.name, svc.port)

        target_ip = team_mgr.get_ip(args.team, args.service)
        target_port = team_mgr.get_port(args.service)

        print(f"Testing exploits for {args.service} against team {args.team} ({target_ip}:{target_port})")

        async def _test():
            flags = await mgr.run_exploit(args.service, target_ip, target_port)
            if flags:
                print(f"  Captured {len(flags)} flag(s):")
                for f in flags:
                    print(f"    {f}")
            else:
                print("  No flags captured.")

        asyncio.run(_test())

    elif args.action == "remove":
        if not args.script:
            print("Error: --script required for 'remove'")
            sys.exit(1)
        if mgr.remove_exploit(args.service, args.script):
            print(f"Removed: {args.script}")
        else:
            print(f"Not found: {args.script}")


def cmd_patch(args: argparse.Namespace) -> None:
    """Manage patches."""
    from .defense.patcher import ServicePatcher

    config = _load_config_optional(args)
    patcher = ServicePatcher(
        service_dir=config.patch_dir if config else "./services",
        backup_dir=config.backup_dir if config else "./backups",
    )

    if args.action == "apply":
        if not args.patch_file:
            print("Error: --patch-file required for 'apply'")
            sys.exit(1)

        # Backup first
        patcher.backup_service(args.service)

        patch_path = Path(args.patch_file)
        if patch_path.suffix == ".json":
            # Binary patch specification
            patch_data = json.loads(patch_path.read_text())
            patches = []
            for p in patch_data.get("patches", []):
                patches.append({
                    "offset": int(p["offset"], 16) if isinstance(p["offset"], str) else p["offset"],
                    "original_bytes": bytes.fromhex(p.get("original", "")),
                    "new_bytes": bytes.fromhex(p["new"]),
                })
            binary = patch_data.get("binary", "")
            if binary:
                result = patcher.patch_binary(binary, patches)
            else:
                print("Error: 'binary' key required in patch JSON")
                sys.exit(1)
        else:
            # Source-level patch
            vuln_type = args.vuln_type or "buffer_overflow"
            result = patcher.patch_source(args.patch_file, vuln_type)

        if result.success:
            print(f"Patch applied: {result.message}")
        else:
            print(f"Patch failed: {result.message}")
            sys.exit(1)

    elif args.action == "rollback":
        result = patcher.rollback(args.service)
        if result.success:
            print(f"Rollback: {result.message}")
        else:
            print(f"Rollback failed: {result.message}")

    elif args.action == "list":
        for service, patches in patcher.applied_patches.items():
            print(f"\n  {service}:")
            for p in patches:
                print(f"    - {p}")
        if not patcher.applied_patches:
            print("No patches applied in this session.")


def cmd_traffic(args: argparse.Namespace) -> None:
    """Analyze traffic."""
    from .defense.traffic_analyzer import TrafficAnalyzer

    config = _load_config_optional(args)
    analyzer = TrafficAnalyzer(
        interface=args.interface or (config.network.game_interface if config else "game"),
        our_team_id=config.network.our_team_id if config else 1,
    )

    if args.action == "capture":
        output_dir = args.output or (config.pcap_dir if config else "./pcaps")
        duration = args.duration or 60
        pcap_path = analyzer.start_capture(output_dir, duration=duration)
        if pcap_path:
            print(f"Capturing traffic -> {pcap_path}")
            print(f"Duration: {duration}s. Press Ctrl+C to stop early.")
            try:
                time.sleep(duration)
            except KeyboardInterrupt:
                pass
            analyzer.stop_capture()
            print("Capture complete.")
        else:
            print("Failed to start capture. Check permissions and interface name.")

    elif args.action == "analyze":
        if not args.pcap:
            print("Error: --pcap required for 'analyze'")
            sys.exit(1)

        attacks = analyzer.analyze_pcap(args.pcap)
        if attacks:
            print(f"Detected {len(attacks)} potential attacks:\n")
            for i, attack in enumerate(attacks, 1):
                print(f"  [{i}] {attack['vuln_type']} (confidence: {attack.get('confidence', '?')})")
                print(f"      Source: {attack.get('source_ip', '?')} -> :{attack.get('dest_port', '?')}")
                payload = attack.get('payload', b'')
                if payload:
                    print(f"      Payload ({len(payload)} bytes): {payload[:40].hex()}...")
                print()
        else:
            print("No attacks detected.")

    elif args.action == "replay":
        if not args.pcap:
            print("Error: --pcap required for 'replay'")
            sys.exit(1)

        payloads = analyzer.extract_exploit_payloads(args.pcap)
        print(f"Extracted {len(payloads)} exploit payload(s)")
        for i, payload in enumerate(payloads):
            print(f"  [{i}] {len(payload)} bytes: {payload[:32].hex()}...")


def cmd_scan(args: argparse.Namespace) -> None:
    """Scan services for vulnerabilities."""
    from .offense.vuln_scanner import VulnScanner

    scanner = VulnScanner()

    if args.binary:
        vulns = scanner.scan_binary(args.binary, args.service)
    elif args.source:
        vulns = scanner.scan_source(args.source, args.service)
    elif args.directory:
        vulns = scanner.scan_directory(args.directory, args.service)
    else:
        print("Error: specify --binary, --source, or --directory")
        sys.exit(1)

    if vulns:
        print(f"Found {len(vulns)} potential vulnerabilities:\n")
        for v in vulns:
            severity_colors = {"critical": "!", "high": "!", "medium": "*", "low": "-"}
            marker = severity_colors.get(v.severity, "?")
            print(f"  [{marker}] {v.severity.upper()}: {v.vuln_type}")
            print(f"      {v.description}")
            if v.location:
                print(f"      Location: {v.location}")
            if v.exploit_hint:
                print(f"      Hint: {v.exploit_hint}")
            print()
    else:
        print("No vulnerabilities detected.")


def cmd_status(args: argparse.Namespace) -> None:
    """Show game status."""
    config = _load_config_optional(args)
    if not config:
        print("Error: --config required for status")
        sys.exit(1)

    engine = GameEngine(config)
    engine.exploit_mgr.load_exploits()

    status = engine.get_status()
    print("Kraken A/D Status")
    print(f"  Running: {status['running']}")
    print(f"  Tick: {status['tick_number']}")
    print(f"  Flags captured: {status['total_flags_captured']}")
    print(f"  Flags accepted: {status['total_flags_accepted']}")
    print(f"  Flags rejected: {status['total_flags_rejected']}")
    print(f"  Attacks detected: {status['total_attacks_detected']}")
    print(f"  Patches applied: {status['total_patches_applied']}")
    print(f"\n  Exploits loaded:")
    for svc, count in status.get("exploits_loaded", {}).items():
        print(f"    {svc}: {count} exploit(s)")


def cmd_scoreboard(args: argparse.Namespace) -> None:
    """Show scoreboard."""
    from .infra.scoreboard import ScoreboardTracker

    tracker = ScoreboardTracker()

    if args.file:
        tracker.load_from_file(args.file)
    else:
        config = _load_config_optional(args)
        if config and config.scoring.scorebot_url:
            asyncio.run(
                tracker.fetch(
                    config.scoring.scorebot_url,
                    config.scoring.scorebot_token,
                )
            )
        else:
            print("Error: provide --file or --config with scorebot_url")
            sys.exit(1)

    print(tracker.print_standings(args.top or 10))


def _load_config_optional(args: argparse.Namespace) -> Optional[GameConfig]:
    """Try to load config from args.config if provided."""
    config_path = getattr(args, "config", None)
    if config_path and Path(config_path).exists():
        return load_config(config_path)
    return None


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Kraken Attack/Defense Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  kraken-ad start --config game.yaml
  kraken-ad start --config game.yaml --dry-run
  kraken-ad exploit list --service vuln1 --config game.yaml
  kraken-ad exploit test --service vuln1 --team 5 --config game.yaml
  kraken-ad patch apply --service vuln1 --patch-file fix.json
  kraken-ad traffic analyze --pcap tick_42.pcap
  kraken-ad scan --binary /opt/services/vuln1 --service vuln1
  kraken-ad status --config game.yaml
  kraken-ad scoreboard --config game.yaml
""",
    )

    parser.add_argument("--config", help="Game config YAML file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    subparsers = parser.add_subparsers(dest="command")

    # kraken-ad start
    start_p = subparsers.add_parser("start", help="Start game engine")
    start_p.add_argument("--config", required=True, help="Game config YAML file")
    start_p.add_argument("--tick", type=int, help="Override tick duration (seconds)")
    start_p.add_argument("--dry-run", action="store_true", help="Don't submit flags")

    # kraken-ad exploit
    exploit_p = subparsers.add_parser("exploit", help="Manage exploits")
    exploit_p.add_argument(
        "action",
        choices=["add", "list", "test", "remove"],
        help="Exploit action",
    )
    exploit_p.add_argument("--service", required=True, help="Service name")
    exploit_p.add_argument("--script", help="Exploit script path")
    exploit_p.add_argument("--team", type=int, help="Test against specific team")
    exploit_p.add_argument("--exploit-dir", help="Override exploit directory")

    # kraken-ad patch
    patch_p = subparsers.add_parser("patch", help="Manage patches")
    patch_p.add_argument(
        "action",
        choices=["apply", "rollback", "list"],
        help="Patch action",
    )
    patch_p.add_argument("--service", required=True, help="Service name")
    patch_p.add_argument("--patch-file", help="Patch file to apply")
    patch_p.add_argument(
        "--vuln-type",
        choices=["buffer_overflow", "format_string", "sql_injection", "command_injection", "path_traversal"],
        help="Vulnerability type for source patches",
    )

    # kraken-ad traffic
    traffic_p = subparsers.add_parser("traffic", help="Analyze traffic")
    traffic_p.add_argument(
        "action",
        choices=["capture", "analyze", "replay"],
        help="Traffic action",
    )
    traffic_p.add_argument("--pcap", help="PCAP file to analyze")
    traffic_p.add_argument("--interface", default="game", help="Capture interface")
    traffic_p.add_argument("--duration", type=int, help="Capture duration (seconds)")
    traffic_p.add_argument("--output", help="Output directory for captures")

    # kraken-ad scan
    scan_p = subparsers.add_parser("scan", help="Scan for vulnerabilities")
    scan_p.add_argument("--service", default="", help="Service name")
    scan_p.add_argument("--binary", help="Binary to scan")
    scan_p.add_argument("--source", help="Source file to scan")
    scan_p.add_argument("--directory", help="Directory to scan recursively")

    # kraken-ad status
    status_p = subparsers.add_parser("status", help="Show game status")
    status_p.add_argument("--config", required=True, help="Game config YAML file")

    # kraken-ad scoreboard
    scoreboard_p = subparsers.add_parser("scoreboard", help="Show scoreboard")
    scoreboard_p.add_argument("--file", help="Load scoreboard from JSON file")
    scoreboard_p.add_argument("--top", type=int, default=10, help="Show top N teams")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "start": cmd_start,
        "exploit": cmd_exploit,
        "patch": cmd_patch,
        "traffic": cmd_traffic,
        "scan": cmd_scan,
        "status": cmd_status,
        "scoreboard": cmd_scoreboard,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

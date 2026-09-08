"""Dynamic firewall rules for blocking detected attacks.

Manages iptables/nftables rules to:
- Block specific exploit payloads by pattern matching
- Rate-limit connections from aggressive attackers
- Whitelist SLA checker IPs
- Block specific teams from specific services (nuclear option)

All rules are tracked internally so they can be listed and flushed cleanly.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("kraken.ad.defense.firewall")


@dataclass
class FirewallRule:
    """Representation of a single firewall rule."""

    rule_type: str  # block_payload, rate_limit, whitelist, block_team
    description: str
    iptables_args: List[str]
    active: bool = True


class DynamicFirewall:
    """Manage dynamic iptables rules for blocking detected attacks.

    All rules are added to a custom chain (KRAKEN_AD) to avoid conflicts
    with existing firewall rules. The chain is created on first use and
    can be flushed without affecting other rules.

    Requires root/sudo privileges for iptables commands.
    """

    CHAIN_NAME = "KRAKEN_AD"

    def __init__(self, use_sudo: bool = True, dry_run: bool = False):
        """Initialize the dynamic firewall.

        Args:
            use_sudo: Prefix iptables commands with sudo.
            dry_run: Log commands instead of executing them.
        """
        self.use_sudo = use_sudo
        self.dry_run = dry_run
        self.rules: List[FirewallRule] = []
        self._chain_created = False

    def _run(self, args: List[str]) -> bool:
        """Execute an iptables command."""
        cmd = []
        if self.use_sudo:
            cmd = ["sudo"]
        cmd.extend(["iptables"] + args)

        if self.dry_run:
            logger.info("DRY RUN: %s", " ".join(cmd))
            return True

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning("iptables failed: %s", result.stderr.strip())
                return False
            return True
        except FileNotFoundError:
            logger.warning("iptables not found -- firewall rules disabled")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("iptables command timed out")
            return False
        except Exception as exc:
            logger.warning("iptables error: %s", exc)
            return False

    def _ensure_chain(self) -> None:
        """Create the KRAKEN_AD chain if it doesn't exist."""
        if self._chain_created:
            return

        # Create chain (ignore error if exists)
        self._run(["-N", self.CHAIN_NAME])

        # Insert jump to our chain in INPUT (if not already there)
        # Check first to avoid duplicates
        check = subprocess.run(
            (["sudo"] if self.use_sudo else [])
            + ["iptables", "-C", "INPUT", "-j", self.CHAIN_NAME],
            capture_output=True,
            timeout=5,
        )
        if check.returncode != 0:
            self._run(["-I", "INPUT", "1", "-j", self.CHAIN_NAME])

        self._chain_created = True

    def block_payload(
        self,
        pattern: bytes,
        service_port: int,
        description: str = "",
    ) -> bool:
        """Add iptables rule to block specific payload pattern.

        Uses the ``string`` match module with ``--hex-string`` to drop
        packets containing the exploit payload.

        Args:
            pattern: Byte pattern to block.
            service_port: Destination port to match.
            description: Human-readable description of what this blocks.
        """
        self._ensure_chain()

        hex_pattern = "|" + " ".join(f"{b:02x}" for b in pattern[:128]) + "|"
        args = [
            "-A", self.CHAIN_NAME,
            "-p", "tcp",
            "--dport", str(service_port),
            "-m", "string",
            "--hex-string", hex_pattern,
            "--algo", "bm",
            "-j", "DROP",
        ]

        desc = description or f"Block payload on port {service_port}"
        rule = FirewallRule(
            rule_type="block_payload",
            description=desc,
            iptables_args=args,
        )

        if self._run(args):
            self.rules.append(rule)
            logger.info("Blocked payload pattern on port %d: %s", service_port, desc)
            return True
        return False

    def rate_limit(
        self,
        source_ip: str,
        port: int,
        rate: str = "10/s",
        burst: int = 20,
    ) -> bool:
        """Rate limit connections from a specific IP to a port.

        Args:
            source_ip: Source IP to rate limit.
            port: Destination port.
            rate: Rate limit string (e.g., "10/s", "30/m").
            burst: Maximum burst before limiting kicks in.
        """
        self._ensure_chain()

        args = [
            "-A", self.CHAIN_NAME,
            "-p", "tcp",
            "-s", source_ip,
            "--dport", str(port),
            "-m", "hashlimit",
            "--hashlimit-above", rate,
            "--hashlimit-burst", str(burst),
            "--hashlimit-name", f"kraken_{source_ip}_{port}",
            "--hashlimit-mode", "srcip",
            "-j", "DROP",
        ]

        desc = f"Rate limit {source_ip} on port {port} to {rate}"
        rule = FirewallRule(
            rule_type="rate_limit",
            description=desc,
            iptables_args=args,
        )

        if self._run(args):
            self.rules.append(rule)
            logger.info("Rate limiting %s on port %d: %s", source_ip, port, rate)
            return True
        return False

    def allow_sla_checker(self, checker_ips: List[str]) -> bool:
        """Whitelist SLA checker IPs so they are never blocked.

        These rules are inserted at the TOP of the chain so they take
        priority over any block rules.
        """
        self._ensure_chain()

        success = True
        for ip in checker_ips:
            args = [
                "-I", self.CHAIN_NAME, "1",  # Insert at top
                "-s", ip,
                "-j", "ACCEPT",
            ]

            desc = f"Whitelist SLA checker {ip}"
            rule = FirewallRule(
                rule_type="whitelist",
                description=desc,
                iptables_args=args,
            )

            if self._run(args):
                self.rules.append(rule)
                logger.info("Whitelisted SLA checker: %s", ip)
            else:
                success = False

        return success

    def block_team(self, team_ip: str, port: int) -> bool:
        """Block a specific team from a service (nuclear option).

        Use sparingly -- this completely blocks a team from accessing
        the service, which may be noticed by organizers.

        Args:
            team_ip: Team's IP address or subnet.
            port: Service port to block.
        """
        self._ensure_chain()

        args = [
            "-A", self.CHAIN_NAME,
            "-p", "tcp",
            "-s", team_ip,
            "--dport", str(port),
            "-j", "DROP",
        ]

        desc = f"Block team {team_ip} from port {port}"
        rule = FirewallRule(
            rule_type="block_team",
            description=desc,
            iptables_args=args,
        )

        if self._run(args):
            self.rules.append(rule)
            logger.info("Blocked team %s from port %d", team_ip, port)
            return True
        return False

    def list_rules(self) -> List[str]:
        """Show current rules managed by Kraken A/D."""
        return [
            f"[{r.rule_type}] {r.description}"
            for r in self.rules
            if r.active
        ]

    def flush(self) -> bool:
        """Remove all Kraken A/D firewall rules.

        Flushes the KRAKEN_AD chain and removes the jump from INPUT.
        """
        if not self._chain_created:
            return True

        # Flush our chain
        success = self._run(["-F", self.CHAIN_NAME])

        # Remove jump from INPUT
        self._run(["-D", "INPUT", "-j", self.CHAIN_NAME])

        # Delete chain
        self._run(["-X", self.CHAIN_NAME])

        self._chain_created = False
        count = len(self.rules)
        self.rules.clear()

        logger.info("Flushed %d firewall rules", count)
        return success

    def remove_rule(self, index: int) -> bool:
        """Remove a specific rule by index."""
        if index < 0 or index >= len(self.rules):
            return False

        rule = self.rules[index]

        # Convert -A to -D for deletion
        delete_args = list(rule.iptables_args)
        for i, arg in enumerate(delete_args):
            if arg == "-A":
                delete_args[i] = "-D"
                break
            elif arg == "-I":
                delete_args[i] = "-D"
                # Remove the position argument (e.g., "1")
                if i + 2 < len(delete_args) and delete_args[i + 2].isdigit():
                    del delete_args[i + 2]
                break

        if self._run(delete_args):
            rule.active = False
            logger.info("Removed rule: %s", rule.description)
            return True
        return False

    def block_team_timed(self, team_ip: str, duration: int = 300) -> bool:
        """Block all traffic from a specific team IP for duration seconds.

        Unlike :meth:`block_team` (which blocks a single port), this drops
        *all* traffic from the given IP.  An automatic unblock is scheduled
        after *duration* seconds.

        Args:
            team_ip: Source IP address to block.
            duration: Seconds before the rule is automatically removed.
                      Pass 0 for a permanent block.
        """
        self._ensure_chain()

        args = ["-A", self.CHAIN_NAME, "-s", team_ip, "-j", "DROP"]

        desc = f"Timed block {team_ip} for {duration}s"
        rule = FirewallRule(
            rule_type="block_team",
            description=desc,
            iptables_args=args,
        )

        if self._run(args):
            self.rules.append(rule)
            logger.info("Blocked team %s for %d seconds", team_ip, duration)

            # Schedule automatic unblock
            if duration > 0:
                try:
                    loop = asyncio.get_event_loop()
                    loop.call_later(duration, self._unblock_team, team_ip)
                except RuntimeError:
                    # No running event loop -- silently skip auto-unblock
                    logger.debug(
                        "No event loop; timed unblock for %s must be done manually",
                        team_ip,
                    )
            return True
        return False

    def _unblock_team(self, team_ip: str) -> None:
        """Remove the timed-block rule for *team_ip*."""
        args = ["-D", self.CHAIN_NAME, "-s", team_ip, "-j", "DROP"]
        if self._run(args):
            # Mark the matching rule as inactive
            for rule in self.rules:
                if (
                    rule.active
                    and rule.rule_type == "block_team"
                    and team_ip in rule.description
                    and "Timed" in rule.description
                ):
                    rule.active = False
                    break
            logger.info("Unblocked team %s (timed block expired)", team_ip)

    def whitelist_ip(self, ip: str) -> bool:
        """Whitelist an IP (e.g., SLA checker) -- insert at top of chain.

        This is a convenience wrapper around :meth:`allow_sla_checker` for a
        single address.
        """
        self._ensure_chain()

        args = ["-I", self.CHAIN_NAME, "1", "-s", ip, "-j", "ACCEPT"]

        desc = f"Whitelist {ip}"
        rule = FirewallRule(
            rule_type="whitelist",
            description=desc,
            iptables_args=args,
        )

        if self._run(args):
            self.rules.append(rule)
            logger.info("Whitelisted IP: %s", ip)
            return True
        return False

    def block_payload_pattern(
        self,
        hex_pattern: str,
        service_port: Optional[int] = None,
    ) -> bool:
        """Block packets containing a specific hex payload pattern.

        Args:
            hex_pattern: Hex string (e.g. ``"deadbeef"``).  Will be wrapped
                         in ``|...|`` for iptables ``--hex-string``.
            service_port: If given, restrict the rule to this destination port.
        """
        self._ensure_chain()

        args = [
            "-A", self.CHAIN_NAME,
            "-m", "string",
            "--hex-string", f"|{hex_pattern}|",
            "--algo", "bm",
        ]
        if service_port:
            args.extend(["-p", "tcp", "--dport", str(service_port)])
        args.extend(["-j", "DROP"])

        desc = f"Block payload pattern {hex_pattern[:16]}... on port {service_port or 'any'}"
        rule = FirewallRule(
            rule_type="block_payload",
            description=desc,
            iptables_args=args,
        )

        if self._run(args):
            self.rules.append(rule)
            logger.info(
                "Blocked payload pattern (port=%s): %s...",
                service_port or "any",
                hex_pattern[:32],
            )
            return True
        return False

    def rate_limit_port(
        self,
        service_port: int,
        max_per_second: int = 10,
    ) -> bool:
        """Rate limit connections to a service port (all sources).

        Adds two rules:
        1. Drop connections above the ``connlimit`` threshold.
        2. Accept connections within the ``limit`` rate.

        This differs from :meth:`rate_limit`, which targets a *specific*
        source IP with ``hashlimit``.

        Args:
            service_port: TCP destination port to rate-limit.
            max_per_second: Maximum new connections per second.
        """
        self._ensure_chain()

        connlimit_args = [
            "-A", self.CHAIN_NAME,
            "-p", "tcp",
            "--dport", str(service_port),
            "-m", "connlimit",
            "--connlimit-above", str(max_per_second),
            "-j", "DROP",
        ]

        limit_args = [
            "-A", self.CHAIN_NAME,
            "-p", "tcp",
            "--dport", str(service_port),
            "-m", "limit",
            "--limit", f"{max_per_second}/sec",
            "--limit-burst", str(max_per_second * 2),
            "-j", "ACCEPT",
        ]

        success = True
        for args, desc_suffix in [
            (connlimit_args, "connlimit"),
            (limit_args, "rate-accept"),
        ]:
            desc = f"Rate limit port {service_port} ({desc_suffix}, {max_per_second}/s)"
            rule = FirewallRule(
                rule_type="rate_limit",
                description=desc,
                iptables_args=args,
            )
            if self._run(args):
                self.rules.append(rule)
            else:
                success = False

        if success:
            logger.info(
                "Rate limiting port %d to %d conn/s", service_port, max_per_second
            )
        return success

    def auto_block_from_traffic(self, attack_patterns: list[dict]) -> int:
        """Auto-generate firewall rules from detected attack patterns.

        Examines each pattern dict and:
        * Blocks the payload signature (if ``payload_hex`` or ``payload`` is
          present and >= 8 hex chars / 4 bytes).
        * Blocks the source IP entirely if it has attacked 3+ times.

        Args:
            attack_patterns: List of dicts with optional keys ``source_ip``,
                ``payload_hex``, ``payload`` (bytes), ``port``, ``count``.

        Returns:
            Number of firewall rules successfully added.
        """
        rules_added = 0

        for pattern in attack_patterns:
            source_ip = pattern.get("source_ip")
            port = pattern.get("port")

            # Derive hex payload from either "payload_hex" or raw "payload"
            payload_hex = pattern.get("payload_hex", "")
            if not payload_hex:
                raw_payload = pattern.get("payload", b"")
                if isinstance(raw_payload, bytes) and len(raw_payload) >= 4:
                    payload_hex = raw_payload[:64].hex()

            # Block the specific payload signature if we have enough data
            if payload_hex and len(payload_hex) >= 8:
                if self.block_payload_pattern(payload_hex[:64], service_port=port):
                    rules_added += 1

            # If same source IP attacks repeatedly, block the IP entirely
            if source_ip and pattern.get("count", 1) >= 3:
                if self.block_team_timed(source_ip, duration=600):
                    rules_added += 1

        logger.info(
            "auto_block_from_traffic: processed %d patterns, added %d rules",
            len(attack_patterns),
            rules_added,
        )
        return rules_added

    def get_stats(self) -> dict:
        """Return firewall statistics."""
        return {
            "total_rules": len(self.rules),
            "active_rules": sum(1 for r in self.rules if r.active),
            "by_type": {
                rtype: sum(1 for r in self.rules if r.rule_type == rtype and r.active)
                for rtype in ("block_payload", "rate_limit", "whitelist", "block_team")
            },
        }

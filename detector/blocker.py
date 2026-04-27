import subprocess
import time
from audit import write_audit


class Blocker:
    """Manages iptables bans and auto-unban schedule."""

    def __init__(self, config):
        self.ban_schedule = config["blocking"]["ban_schedule_minutes"]
        # ip -> {ban_time, unban_time, ban_count, permanent}
        self.banned = {}

    def is_banned(self, ip):
        return ip in self.banned

    def ban(self, ip, reason, rate, baseline_mean):
        """Add iptables DROP rule for an IP."""
        if ip in self.banned:
            return  # Already banned

        ban_count = 0
        duration = self.ban_schedule[0]

        self.banned[ip] = {
            "ban_time": time.time(),
            "unban_time": time.time() + duration * 60 if duration > 0 else None,
            "ban_count": ban_count,
            "permanent": duration == -1,
            "reason": reason,
            "rate": rate,
            "baseline": baseline_mean
        }

        # Add iptables rule
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )

        duration_str = f"{duration} min" if duration > 0 else "permanent"
        write_audit(
            action="BAN",
            ip=ip,
            condition=reason,
            rate=rate,
            baseline=baseline_mean,
            duration=duration_str
        )

        return duration_str

    def check_unbans(self, notifier):
        """Check and release expired bans."""
        now = time.time()
        to_unban = []

        for ip, info in self.banned.items():
            if info["permanent"]:
                continue
            if info["unban_time"] and now >= info["unban_time"]:
                to_unban.append(ip)

        for ip in to_unban:
            self._unban(ip, notifier)

    def _unban(self, ip, notifier):
        """Remove iptables rule and schedule next ban if reoffending."""
        info = self.banned[ip]
        ban_count = info["ban_count"] + 1

        # Remove iptables rule
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )

        # Determine next ban duration
        if ban_count >= len(self.ban_schedule):
            next_duration = -1  # permanent
        else:
            next_duration = self.ban_schedule[ban_count]

        write_audit(
            action="UNBAN",
            ip=ip,
            condition=info["reason"],
            rate=info["rate"],
            baseline=info["baseline"],
            duration=f"next={next_duration}min"
        )

        notifier.send_unban(
            ip=ip,
            reason=info["reason"],
            next_duration=next_duration
        )

        # Update ban record for potential rebanning
        self.banned[ip]["ban_count"] = ban_count
        self.banned[ip]["ban_time"] = None
        self.banned[ip]["unban_time"] = None
        del self.banned[ip]

    def get_banned_ips(self):
        return list(self.banned.keys())

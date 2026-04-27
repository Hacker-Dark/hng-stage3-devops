import requests
import time


class Notifier:
    """Sends Slack alerts for bans, unbans, and global anomalies."""

    def __init__(self, config):
        self.webhook_url = config["slack"]["webhook_url"]

    def _send(self, message):
        """Send a message to Slack."""
        try:
            requests.post(
                self.webhook_url,
                json={"text": message},
                timeout=5
            )
        except Exception as e:
            print(f"Slack error: {e}")

    def send_ban(self, ip, reason, rate, baseline, duration):
        msg = (
            f"🚨 *IP BANNED*\n"
            f"IP: `{ip}`\n"
            f"Condition: {reason}\n"
            f"Rate: {rate:.2f} req/s\n"
            f"Baseline: {baseline:.2f} req/s\n"
            f"Duration: {duration}\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
        )
        self._send(msg)

    def send_unban(self, ip, reason, next_duration):
        duration_str = f"{next_duration} min" if next_duration > 0 else "permanent (if rebanned)"
        msg = (
            f"✅ *IP UNBANNED*\n"
            f"IP: `{ip}`\n"
            f"Original reason: {reason}\n"
            f"Next ban duration if reoffending: {duration_str}\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
        )
        self._send(msg)

    def send_global_alert(self, reason, rate, baseline):
        msg = (
            f"⚠️ *GLOBAL TRAFFIC ANOMALY*\n"
            f"Condition: {reason}\n"
            f"Global Rate: {rate:.2f} req/s\n"
            f"Baseline: {baseline:.2f} req/s\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
        )
        self._send(msg)

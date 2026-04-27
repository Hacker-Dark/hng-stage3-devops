import time
import yaml
import psutil
import threading
from monitor import tail_log
from baseline import BaselineTracker
from detector import SlidingWindow, AnomalyDetector
from blocker import Blocker
from notifier import Notifier
from dashboard import start_dashboard
from audit import write_audit

# Load config
with open("config.yaml") as f:
    config = yaml.safe_load(f)

# Initialize components
baseline = BaselineTracker(config)
window = SlidingWindow(config)
detector = AnomalyDetector(config)
blocker = Blocker(config)
notifier = Notifier(config)

# Shared state for dashboard
state = {
    "global_rate": 0,
    "baseline_mean": 0,
    "baseline_stddev": 0,
    "banned_ips": [],
    "top_ips": [],
    "cpu": 0,
    "memory": 0,
}

start_time = time.time()


def update_state():
    """Update dashboard state every 3 seconds."""
    while True:
        state["global_rate"] = window.get_global_rate()
        state["baseline_mean"] = baseline.effective_mean
        state["baseline_stddev"] = baseline.effective_stddev
        state["banned_ips"] = [
            {
                "ip": ip,
                "reason": blocker.banned[ip]["reason"],
                "rate": blocker.banned[ip]["rate"],
                "ban_time": time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.gmtime(blocker.banned[ip]["ban_time"])
                )
            }
            for ip in blocker.get_banned_ips()
            if ip in blocker.banned
        ]
        state["top_ips"] = window.get_top_ips(10)
        state["cpu"] = psutil.cpu_percent()
        state["memory"] = psutil.virtual_memory().percent
        time.sleep(3)


def check_unbans():
    """Check for unbans every 30 seconds."""
    while True:
        blocker.check_unbans(notifier)
        time.sleep(30)


# Start dashboard
start_dashboard(config["dashboard"]["port"], state)

# Start background threads
threading.Thread(target=update_state, daemon=True).start()
threading.Thread(target=check_unbans, daemon=True).start()

print("Anomaly detection engine started...")
write_audit("STARTUP", ip="system", condition="daemon started",
            rate=0, baseline=0, duration="indefinite")

# Main loop
for entry in tail_log(config["log_path"]):
    ip = entry["ip"]
    is_error = entry["status"] >= 400

    # Skip private/local IPs
    if ip.startswith("172.") or ip.startswith("10.") or ip == "127.0.0.1":
        baseline.record_request(is_error)
        window.record(ip, is_error)
        continue

    # Record in baseline and window
    baseline.record_request(is_error)
    window.record(ip, is_error)

    # Skip already banned IPs
    if blocker.is_banned(ip):
        continue

    # Check per-IP anomaly
    ip_rate = window.get_ip_rate(ip)
    ip_error_rate = window.get_ip_error_rate(ip)
    is_anomalous, reason = detector.check_ip(
        ip, ip_rate, ip_error_rate, baseline
    )

    if is_anomalous:
        duration = blocker.ban(ip, reason, ip_rate, baseline.effective_mean)
        if duration:
            notifier.send_ban(
                ip=ip,
                reason=reason,
                rate=ip_rate,
                baseline=baseline.effective_mean,
                duration=duration
            )

    # Check global anomaly
    global_rate = window.get_global_rate()
    is_global, global_reason = detector.check_global(global_rate, baseline)
    if is_global:
        notifier.send_global_alert(
            reason=global_reason,
            rate=global_rate,
            baseline=baseline.effective_mean
        )

import time
import os

AUDIT_LOG = "/var/log/detector/audit.log"


def write_audit(action, ip="global", condition="", rate=0, baseline=0, duration=""):
    """Write a structured audit log entry."""
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = (
        f"[{timestamp}] {action} {ip} | "
        f"condition={condition} | "
        f"rate={rate:.2f} | "
        f"baseline={baseline:.2f} | "
        f"duration={duration}\n"
    )
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    with open(AUDIT_LOG, "a") as f:
        f.write(line)
    print(line.strip())

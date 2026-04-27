import json
import time
import os


def tail_log(log_path):
    """Continuously tail the nginx log file line by line."""
    while not os.path.exists(log_path):
        print(f"Waiting for log file: {log_path}")
        time.sleep(2)

    with open(log_path, "r") as f:
        # Go to end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            line = line.strip()
            if line:
                entry = parse_line(line)
                if entry:
                    yield entry


def parse_line(line):
    """Parse a JSON log line into a dict."""
    try:
        data = json.loads(line)
        return {
            "ip": data.get("source_ip", ""),
            "timestamp": data.get("timestamp", ""),
            "method": data.get("method", ""),
            "path": data.get("path", ""),
            "status": int(data.get("status", 0)),
            "size": int(data.get("response_size", 0)),
        }
    except (json.JSONDecodeError, ValueError):
        return None

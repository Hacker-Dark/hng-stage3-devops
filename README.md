# hng-stage3-devops
# HNG Stage 3 — Anomaly Detection Engine

A real-time HTTP traffic anomaly detection and DDoS protection tool built alongside a Nextcloud deployment.

## Live URLs
- **Metrics Dashboard:** (http://mordecai-monitor.crabdance.com:8080/)
- **Server IP:** 16.16.94.59
- **Nextcloud:** http://16.16.94.59

## Language Choice
Built in **Python** because:
- Fast development cycle for a time-sensitive task
- Rich standard library (collections.deque, threading, http.server)
- Easy to read and explain during live interviews
- No external rate-limiting libraries used — all logic is custom

## Architecture
Nginx (JSON logs) → HNG-nginx-logs volume → Detector daemon
↓
Sliding Window (deque)
↓
Baseline (rolling 30min)
↓
Anomaly Detector (z-score)
↓
┌───────────────┴───────────────┐
Blocker                        Notifier
(iptables)                        (Slack)
↓
Unbanner
(backoff schedule)

## How the Sliding Window Works
The sliding window uses Python's `collections.deque` to track request timestamps.

For each incoming request:
1. The current timestamp is appended to the IP's deque and the global deque
2. Any timestamps older than 60 seconds are evicted from the left of the deque
3. The request rate is calculated as `len(deque) / 60`

This gives an accurate real-time requests-per-second count without any counters
or approximations. Old entries are evicted automatically as new ones come in.

```python
self.ip_windows[ip].append(now)
while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
    self.ip_windows[ip].popleft()
```

## How the Baseline Works
- **Window size:** 30 minutes of per-second request counts
- **Recalculation interval:** Every 60 seconds
- **Per-hour slots:** Traffic is grouped by hour — current hour's data is
  preferred when it has enough samples (min 5)
- **Floor values:** mean floor = 0.1, stddev floor = 0.1 to avoid
  division by zero on fresh starts
- Every 60 seconds, mean and stddev are recalculated from the rolling window:

```python
mean = sum(samples) / len(samples)
variance = sum((x - mean) ** 2 for x in samples) / len(samples)
stddev = math.sqrt(variance)
```

## How Detection Works
Two conditions trigger a ban — whichever fires first:

1. **Z-score:** `(ip_rate - mean) / stddev > 1.5`
   — measures how many standard deviations above normal the IP is

2. **Rate multiplier:** `ip_rate > 1.5 * mean`
   — catches spikes even when stddev is low

If an IP's error rate (4xx/5xx) is 3x the baseline error rate, thresholds
are tightened by 30% automatically.

## How iptables Blocking Works
When an IP is flagged as anomalous:

```bash
iptables -I INPUT -s <ip> -j DROP
```

This inserts a DROP rule at the top of the INPUT chain, dropping all packets
from that IP at the kernel level — before they even reach Nginx or the app.

Auto-unban follows a backoff schedule:
- First ban: 10 minutes
- Second ban: 30 minutes  
- Third ban: 2 hours
- Fourth ban: permanent

On each unban:
```bash
iptables -D INPUT -s <ip> -j DROP
```

## Setup Instructions (Fresh VPS)

### Prerequisites
- Ubuntu 22.04
- 2 vCPU, 2GB RAM minimum
- Docker and Docker Compose installed
- Python 3.10+
- iptables

### 1. Clone the repository
```bash
git clone https://github.com/Hacker-Dark/hng-stage3-devops.git
cd hng-stage3-devops
```

### 2. Start the Nextcloud stack
```bash
docker compose up -d
```

### 3. Install detector dependencies
```bash
cd detector
sudo pip3 install -r requirements.txt --break-system-packages
```

### 4. Configure Slack webhook
```bash
nano detector/config.yaml
# Set slack.webhook_url to your Slack webhook URL
```

### 5. Start the detector as a service
```bash
sudo cp detector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable detector
sudo systemctl start detector
```

### 6. Verify everything is running
```bash
# Check stack
docker compose ps

# Check detector
sudo systemctl status detector

# Check dashboard
curl http://localhost:8080

# Check logs
sudo tail -f /var/log/detector/audit.log
```

### Successful startup looks like:
NAME        STATUS
nextcloud   Up (healthy)
nginx       Up
● detector.service - HNG Anomaly Detection Engine
Active: active (running)
Dashboard running on port 8080
Anomaly detection engine started...

## Repository Structure
detector/
main.py         - Entry point, main loop
monitor.py      - Log tailing and parsing
baseline.py     - Rolling baseline tracker
detector.py     - Sliding window and anomaly detection
blocker.py      - iptables ban management
unbanner.py     - Auto-unban with backoff schedule
notifier.py     - Slack alerts
dashboard.py    - Web dashboard
config.yaml     - All thresholds and configuration
requirements.txt
nginx/
nginx.conf      - JSON access log configuration
screenshots/      - Required grading screenshots
README.md
FIXES.md

## Blog Post
https://dev.to/mordecai_amehson/how-i-built-a-real-time-ddos-detection-engine-from-scratch-cll

## GitHub Repository
https://github.com/Hacker-Dark/hng-stage3-devops

import time
import math
from collections import deque, defaultdict


class SlidingWindow:
    """
    Tracks request rates using deque-based sliding windows.
    One window per IP, one global window.
    Evicts entries older than window_seconds automatically.
    """

    def __init__(self, config):
        self.window_seconds = config["sliding_window"]["per_ip_seconds"]
        # Global window: deque of timestamps
        self.global_window = deque()
        # Per-IP windows: dict of ip -> deque of timestamps
        self.ip_windows = defaultdict(deque)
        # Per-IP error counts
        self.ip_errors = defaultdict(deque)

    def record(self, ip, is_error=False):
        """Record a request and evict old entries."""
        now = time.time()
        cutoff = now - self.window_seconds

        # Global window
        self.global_window.append(now)
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()

        # Per-IP window
        self.ip_windows[ip].append(now)
        while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
            self.ip_windows[ip].popleft()

        # Per-IP errors
        if is_error:
            self.ip_errors[ip].append(now)
        while self.ip_errors[ip] and self.ip_errors[ip][0] < cutoff:
            self.ip_errors[ip].popleft()

    def get_global_rate(self):
        """Get global requests per second."""
        return len(self.global_window) / self.window_seconds

    def get_ip_rate(self, ip):
        """Get per-IP requests per second."""
        return len(self.ip_windows[ip]) / self.window_seconds

    def get_ip_error_rate(self, ip):
        """Get per-IP error rate per second."""
        return len(self.ip_errors[ip]) / self.window_seconds

    def get_top_ips(self, n=10):
        """Get top N IPs by request count."""
        return sorted(
            [(ip, len(window)) for ip, window in self.ip_windows.items()],
            key=lambda x: x[1],
            reverse=True
        )[:n]


class AnomalyDetector:
    """
    Detects anomalies using z-score and rate multiplier thresholds.
    """

    def __init__(self, config):
        self.z_threshold = config["detection"]["z_score_threshold"]
        self.rate_multiplier = config["detection"]["rate_multiplier_threshold"]
        self.error_multiplier = config["detection"]["error_rate_multiplier"]

    def check_ip(self, ip, ip_rate, ip_error_rate, baseline):
        """
        Check if an IP is anomalous.
        Returns (is_anomalous, reason)
        """
        mean = baseline.effective_mean
        stddev = baseline.effective_stddev

        # Tighten thresholds if high error rate
        z_threshold = self.z_threshold
        rate_multiplier = self.rate_multiplier
        if baseline.error_mean > 0:
            if ip_error_rate > self.error_multiplier * baseline.error_mean:
                z_threshold = z_threshold * 0.7
                rate_multiplier = rate_multiplier * 0.7

        # Z-score check
        if stddev > 0:
            z_score = (ip_rate - mean) / stddev
            if z_score > z_threshold:
                return True, f"z-score={z_score:.2f} threshold={z_threshold}"

        # Rate multiplier check
        if mean > 0 and ip_rate > rate_multiplier * mean:
            return True, f"rate={ip_rate:.2f} is {ip_rate/mean:.1f}x baseline"

        return False, ""

    def check_global(self, global_rate, baseline):
        """
        Check if global traffic is anomalous.
        Returns (is_anomalous, reason)
        """
        mean = baseline.effective_mean
        stddev = baseline.effective_stddev

        if stddev > 0:
            z_score = (global_rate - mean) / stddev
            if z_score > self.z_threshold:
                return True, f"global z-score={z_score:.2f}"

        if mean > 0 and global_rate > self.rate_multiplier * mean:
            return True, f"global rate={global_rate:.2f} is {global_rate/mean:.1f}x baseline"

        return False, ""

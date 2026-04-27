import time
import math
from collections import deque, defaultdict


class BaselineTracker:
    """
    Tracks rolling baseline of requests per second.
    Maintains a 30-minute window of per-second counts.
    Recalculates mean and stddev every 60 seconds.
    Maintains per-hour slots and prefers current hour when enough data exists.
    """

    def __init__(self, config):
        self.window_minutes = config["baseline"]["window_minutes"]
        self.recalc_interval = config["baseline"]["recalculate_every_seconds"]
        self.min_samples = config["baseline"]["min_samples"]
        self.floor_mean = config["baseline"]["floor_mean"]
        self.floor_stddev = config["baseline"]["floor_stddev"]

        # Rolling window of (timestamp, count) tuples
        self.window = deque()
        self.current_second_count = 0
        self.current_second = int(time.time())

        # Per-hour slots
        self.hourly_slots = defaultdict(list)

        # Current baseline values
        self.effective_mean = self.floor_mean
        self.effective_stddev = self.floor_stddev

        # Error rate baseline
        self.error_mean = self.floor_mean
        self.error_stddev = self.floor_stddev
        self.error_window = deque()

        self.last_recalc = time.time()
        self.history = []  # for dashboard graph

    def record_request(self, is_error=False):
        """Record an incoming request."""
        now = int(time.time())
        if now != self.current_second:
            # Save the completed second
            self.window.append((self.current_second, self.current_second_count))
            hour = time.gmtime(self.current_second).tm_hour
            self.hourly_slots[hour].append(self.current_second_count)

            # Evict entries older than window_minutes
            cutoff = now - (self.window_minutes * 60)
            while self.window and self.window[0][0] < cutoff:
                self.window.popleft()

            self.current_second = now
            self.current_second_count = 0

        self.current_second_count += 1

        if is_error:
            self.error_window.append(time.time())
            cutoff = time.time() - 60
            while self.error_window and self.error_window[0] < cutoff:
                self.error_window.popleft()

        # Recalculate if interval has passed
        if time.time() - self.last_recalc >= self.recalc_interval:
            self._recalculate()

    def _recalculate(self):
        """Recalculate mean and stddev from rolling window."""
        self.last_recalc = time.time()

        # Prefer current hour's data if enough samples
        current_hour = time.gmtime().tm_hour
        hourly = self.hourly_slots.get(current_hour, [])

        if len(hourly) >= self.min_samples:
            samples = hourly
        else:
            samples = [count for _, count in self.window]

        if len(samples) < self.min_samples:
            return

        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        stddev = math.sqrt(variance)

        self.effective_mean = max(mean, self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)

        # Track history for dashboard graph
        self.history.append({
            "timestamp": time.time(),
            "mean": self.effective_mean,
            "stddev": self.effective_stddev,
            "hour": current_hour
        })
        if len(self.history) > 100:
            self.history.pop(0)

    def get_error_rate(self):
        """Get current error rate per second."""
        return len(self.error_window) / 60.0

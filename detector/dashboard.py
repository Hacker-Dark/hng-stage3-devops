import psutil
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading


class DashboardHandler(BaseHTTPRequestHandler):
    state = {}

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def do_GET(self):
        if self.path == "/api/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(self.state).encode())
        elif self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self.get_html().encode())
        else:
            self.send_response(404)
            self.end_headers()

    def get_html(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector</title>
    <style>
        body { background: #0a0a0a; color: #e8e8e8; font-family: 'Courier New', monospace; padding: 2rem; }
        h1 { color: #fff; border-bottom: 1px solid #333; padding-bottom: 1rem; }
        .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin: 1rem 0; }
        .card { background: #111; border: 1px solid #222; border-radius: 4px; padding: 1rem; }
        .card h3 { color: #888; font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; margin: 0 0 0.5rem; }
        .card .val { font-size: 24px; color: #fff; }
        .banned { color: #ff4444; }
        .good { color: #4ade80; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th { text-align: left; color: #555; font-size: 11px; padding: 0.5rem; border-bottom: 1px solid #222; }
        td { padding: 0.5rem; border-bottom: 1px solid #111; font-size: 13px; }
        .status { color: #4ade80; font-size: 11px; }
    </style>
</head>
<body>
    <h1>🛡️ HNG Anomaly Detection Engine</h1>
    <p class="status" id="status">Connecting...</p>

    <div class="grid">
        <div class="card">
            <h3>Global Req/s</h3>
            <div class="val" id="global_rate">-</div>
        </div>
        <div class="card">
            <h3>Baseline Mean</h3>
            <div class="val" id="baseline_mean">-</div>
        </div>
        <div class="card">
            <h3>Baseline StdDev</h3>
            <div class="val" id="baseline_stddev">-</div>
        </div>
        <div class="card">
            <h3>Banned IPs</h3>
            <div class="val banned" id="banned_count">-</div>
        </div>
        <div class="card">
            <h3>CPU Usage</h3>
            <div class="val" id="cpu">-</div>
        </div>
        <div class="card">
            <h3>Memory Usage</h3>
            <div class="val" id="memory">-</div>
        </div>
    </div>

    <h2>Uptime</h2>
    <p id="uptime">-</p>

    <h2>Banned IPs</h2>
    <table>
        <tr><th>IP</th><th>Reason</th><th>Rate</th><th>Banned At</th></tr>
        <tbody id="banned_table"></tbody>
    </table>

    <h2>Top 10 Source IPs</h2>
    <table>
        <tr><th>IP</th><th>Requests (60s window)</th></tr>
        <tbody id="top_ips_table"></tbody>
    </table>

    <script>
        const start = Date.now();
        async function refresh() {
            try {
                const r = await fetch('/api/metrics');
                const d = await r.json();
                document.getElementById('global_rate').textContent = (d.global_rate || 0).toFixed(2) + ' req/s';
                document.getElementById('baseline_mean').textContent = (d.baseline_mean || 0).toFixed(2);
                document.getElementById('baseline_stddev').textContent = (d.baseline_stddev || 0).toFixed(2);
                document.getElementById('banned_count').textContent = (d.banned_ips || []).length;
                document.getElementById('cpu').textContent = (d.cpu || 0).toFixed(1) + '%';
                document.getElementById('memory').textContent = (d.memory || 0).toFixed(1) + '%';
                const uptime = Math.floor((Date.now() - start) / 1000);
                document.getElementById('uptime').textContent = uptime + 's';
                document.getElementById('status').textContent = 'Live — last update: ' + new Date().toLocaleTimeString();

                const bt = document.getElementById('banned_table');
                bt.innerHTML = (d.banned_ips || []).map(b =>
                    `<tr><td>${b.ip}</td><td>${b.reason}</td><td>${b.rate.toFixed(2)}</td><td>${b.ban_time}</td></tr>`
                ).join('');

                const tt = document.getElementById('top_ips_table');
                tt.innerHTML = (d.top_ips || []).map(([ip, count]) =>
                    `<tr><td>${ip}</td><td>${count}</td></tr>`
                ).join('');
            } catch(e) {
                document.getElementById('status').textContent = 'Error connecting...';
            }
        }
        setInterval(refresh, 3000);
        refresh();
    </script>
</body>
</html>"""


def start_dashboard(port, state_ref):
    DashboardHandler.state = state_ref
    server = HTTPServer(("0.0.0.0", port), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Dashboard running on port {port}")

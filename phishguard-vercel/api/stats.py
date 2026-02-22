from http.server import BaseHTTPRequestHandler
import json, random

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps({
            "total_scans_today": random.randint(1200, 1800),
            "threats_blocked":   random.randint(340, 480),
            "emails_analyzed":   random.randint(800, 1100),
            "urls_analyzed":     random.randint(400, 700),
            "avg_scan_time_ms":  round(random.uniform(8, 25), 1),
            "top_threat_type":   "Credential Harvesting",
            "platform":          "Vercel Serverless"
        }).encode())

    def log_message(self, format, *args):
        pass

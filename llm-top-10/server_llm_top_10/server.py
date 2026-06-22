#!/usr/bin/env python3
"""
=============================================================
  VULNERABLE FEEDBACK SERVER — LLM05 Demo
  DO NOT use in production. Intentionally has no sanitization.
=============================================================

Endpoints:
  GET  /                → serves index.html
  GET  /api/feedback    → returns feedback.csv as JSON array
  GET  /feedback.csv    → raw CSV file (for inspection)
  POST /submit          → appends a new row to feedback.csv

Run:
  python server.py
  Then in another terminal:  ngrok http 8080
"""

import json
import csv
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime
from urllib.parse import urlparse

CSV_FILE = "feedback.csv"
HOST = "0.0.0.0"
PORT = 8080


def ensure_csv_exists():
    """Create the CSV with headers if it doesn't exist yet."""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Name", "Summary", "Category", "Timestamp"])
        print(f"[+] Created {CSV_FILE} with headers")


class FeedbackHandler(SimpleHTTPRequestHandler):
    """Handles GET (static + API) and POST (submit feedback)."""

    # ── GET ────────────────────────────────────────────────
    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/feedback":
            self._serve_feedback_json()
        else:
            # Serve static files (index.html, feedback.csv, etc.)
            super().do_GET()

    # ── POST ───────────────────────────────────────────────
    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/submit":
            self._handle_submit()
        else:
            self.send_error(404, "Not Found")

    # ── OPTIONS (CORS preflight) ───────────────────────────
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    # ── Internal handlers ──────────────────────────────────
    def _serve_feedback_json(self):
        """Read feedback.csv and return it as a JSON array."""
        feedbacks = []
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    feedbacks.append(row)

        body = json.dumps(feedbacks, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _handle_submit(self):
        """
        Append submitted feedback to the CSV.
        ⚠️  NO SANITIZATION — values are stored exactly as received.
        """
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length)

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return

        name      = data.get("name", "Anonymous")
        summary   = data.get("summary", "")
        category  = data.get("category", "General")
        timestamp = data.get("timestamp", datetime.now().isoformat())

        # ⚠️  Written as-is — any HTML/JS in 'summary' is preserved
        with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([name, summary, category, timestamp])

        print(f"[+] Saved feedback from '{name}' | Category: {category}")

        body = json.dumps({"status": "ok", "message": "Feedback saved"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    # ── Helpers ────────────────────────────────────────────
    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, fmt, *args):
        """Prefix logs for clarity."""
        print(f"[server] {args[0]} {args[1]} {args[2]}")


# ── Main ──────────────────────────────────────────────────
if __name__ == "__main__":
    ensure_csv_exists()
    server = HTTPServer((HOST, PORT), FeedbackHandler)
    print(f"{'='*55}")
    print(f"  Feedback Server running → http://localhost:{PORT}")
    print(f"  Expose with:  ngrok http {PORT}")
    print(f"{'='*55}")
    server.serve_forever()

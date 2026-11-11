"""
Interactive Web Dashboard HTTP Server.
Pure Python standard library implementation (no Flask/FastAPI required).
Serves real-time data quality KPIs, discrepancy triage, and pipeline re-execution.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import urllib.parse
from typing import Any, Dict, Optional

from integrity_framework.pipeline.orchestrator import ValidationPipeline
from integrity_framework.pipeline.reporter import ReportGenerator


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the interactive integrity dashboard."""

    pipeline: Optional[ValidationPipeline] = None
    latest_summary: Optional[Any] = None

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # Static assets
        if path == "/" or path == "/index.html":
            self._serve_file("index.html", "text/html")
        elif path == "/css/styles.css":
            self._serve_file("styles.css", "text/css")
        elif path == "/js/app.js":
            self._serve_file("app.js", "application/javascript")
        # API Endpoints
        elif path == "/api/summary":
            if not DashboardHandler.latest_summary and DashboardHandler.pipeline:
                DashboardHandler.latest_summary = DashboardHandler.pipeline.run()
            summary_dict = DashboardHandler.latest_summary.to_dict() if DashboardHandler.latest_summary else {}
            self._set_headers(200)
            self.wfile.write(json.dumps(summary_dict).encode("utf-8"))
        elif path == "/api/quarantine":
            if DashboardHandler.pipeline and DashboardHandler.pipeline.quarantine:
                limit = int(params.get("limit", [50])[0])
                status = params.get("status", [None])[0]
                records = DashboardHandler.pipeline.quarantine.list_quarantined(status=status, limit=limit)
                self._set_headers(200)
                self.wfile.write(json.dumps({"success": True, "data": records}).encode("utf-8"))
            else:
                self._set_headers(200)
                self.wfile.write(json.dumps({"success": True, "data": []}).encode("utf-8"))
        elif path == "/api/export":
            fmt = params.get("format", ["json"])[0].lower()
            if not DashboardHandler.latest_summary:
                self._set_headers(400)
                self.wfile.write(b'{"error": "No run data available"}')
                return
            reporter = ReportGenerator(DashboardHandler.latest_summary)
            if fmt == "csv":
                self._set_headers(200, "text/csv")
                self.wfile.write(reporter.to_csv().encode("utf-8"))
            else:
                self._set_headers(200, "application/json")
                self.wfile.write(reporter.to_json().encode("utf-8"))
        else:
            self._set_headers(404, "text/plain")
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/run":
            if DashboardHandler.pipeline:
                DashboardHandler.latest_summary = DashboardHandler.pipeline.run()
                self._set_headers(200)
                self.wfile.write(json.dumps({
                    "success": True,
                    "message": "Validation pipeline completed successfully",
                    "summary": DashboardHandler.latest_summary.to_dict(),
                }).encode("utf-8"))
            else:
                self._set_headers(500)
                self.wfile.write(b'{"success": false, "error": "Pipeline not initialized"}')
        else:
            self._set_headers(404)
            self.wfile.write(b'{"error": "Not Found"}')

    def _serve_file(self, filename: str, content_type: str):
        static_dir = os.path.join(os.path.dirname(__file__), "static")
        file_path = os.path.join(static_dir, filename)
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                content = f.read()
            self._set_headers(200, content_type)
            self.wfile.write(content)
        else:
            self._set_headers(404, "text/plain")
            self.wfile.write(f"File {filename} not found".encode("utf-8"))

    def log_message(self, format, *args):
        # Quiet standard HTTP server logs
        return


def start_server(pipeline: ValidationPipeline, host: str = "127.0.0.1", port: int = 8088):
    DashboardHandler.pipeline = pipeline
    server = HTTPServer((host, port), DashboardHandler)
    print(f"\n🌐 Data Integrity Dashboard running at: http://{host}:{port}")
    print(f"📊 Press Ctrl+C to terminate server.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard server...")
    finally:
        server.server_close()

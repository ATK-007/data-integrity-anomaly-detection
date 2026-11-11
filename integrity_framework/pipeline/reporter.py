"""
Multi-format report generator for data integrity audits and findings investigations.
Exports clean Markdown, JSON, CSV, and self-contained HTML dashboards.
"""

import csv
import io
import json
import os
from typing import Any, Dict, List, Optional
from integrity_framework.models import PipelineSummary, Finding, Severity


class ReportGenerator:
    """
    Renders pipeline summaries and findings into various report formats.
    """

    def __init__(self, summary: PipelineSummary):
        self.summary = summary

    def to_json(self, indent: int = 2) -> str:
        """Export as JSON string."""
        return self.summary.to_json(indent=indent)

    def to_csv(self) -> str:
        """Export all findings as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "finding_id",
            "timestamp",
            "severity",
            "table_name",
            "record_id",
            "column_name",
            "rule_name",
            "check_type",
            "expected_value",
            "actual_value",
            "message",
        ])

        for check in self.summary.check_results:
            for f in check.findings:
                writer.writerow([
                    f.finding_id,
                    f.timestamp,
                    f.severity.value if isinstance(f.severity, Severity) else str(f.severity),
                    f.table_name,
                    f.record_id or "",
                    f.column_name or "",
                    f.rule_name,
                    f.check_type.value if hasattr(f.check_type, "value") else str(f.check_type),
                    str(f.expected_value) if f.expected_value is not None else "",
                    str(f.actual_value) if f.actual_value is not None else "",
                    f.message,
                ])

        return output.getvalue()

    def to_markdown(self) -> str:
        """Export formatted Markdown summary report."""
        s = self.summary
        crit_count = s.findings_by_severity.get("CRITICAL", 0)
        err_count = s.findings_by_severity.get("ERROR", 0)
        warn_count = s.findings_by_severity.get("WARNING", 0)
        info_count = s.findings_by_severity.get("INFO", 0)

        # Status badge determination
        if crit_count > 0 or err_count > 0:
            status_text = "FAILED (Action Required)"
            status_emoji = "❌"
        elif warn_count > 0:
            status_text = "PASSED WITH WARNINGS"
            status_emoji = "⚠️"
        else:
            status_text = "PASSED (Clean)"
            status_emoji = "✅"

        lines = [
            f"# 🛡️ Data Integrity Audit Report: {s.target_name}",
            "",
            f"**Run ID**: `{s.run_id}`  ",
            f"**Execution Timestamp**: `{s.start_time}`  ",
            f"**Elapsed Duration**: `{s.duration_seconds:.3f}s`  ",
            f"**Overall Status**: {status_emoji} **{status_text}**  ",
            f"**Integrity Health Score**: **`{s.integrity_score:.1f}%`**",
            "",
            "---",
            "",
            "## 📊 Executive Metric Summary",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| **Total Records Inspected** | {s.total_records:,} |",
            f"| **Clean / Passed Records** | {s.passed_records:,} |",
            f"| **Flagged Discrepancies** | {s.flagged_records:,} |",
            f"| **Quarantined Records** | {s.quarantined_records:,} |",
            f"| **Critical / Hash Failures** | {crit_count} |",
            f"| **Hard Validation Errors** | {err_count} |",
            f"| **Statistical Anomaly Warnings** | {warn_count} |",
            f"| **Informational Findings** | {info_count} |",
            "",
            "---",
            "",
            "## 🔍 Check Suite Execution Breakdown",
            "",
            "| Check Name | Type | Records | Findings | Duration | Status |",
            "|---|---|---|---|---|---|",
        ]

        for c in s.check_results:
            st = "✅ PASS" if c.passed else "❌ FAIL"
            c_type = c.check_type.value if hasattr(c.check_type, "value") else str(c.check_type)
            lines.append(
                f"| `{c.check_name}` | {c_type} | {c.records_inspected:,} | {len(c.findings)} | {c.execution_time_ms:.1f}ms | {st} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 🚨 Top Discrepancies & Flagged Findings",
            "",
        ])

        # Gather top findings
        all_findings = []
        for c in s.check_results:
            all_findings.extend(c.findings)

        if not all_findings:
            lines.append("> [!NOTE]\n> No anomalies or data discrepancies detected. All integrity assertions satisfied.")
        else:
            lines.append("| ID | Severity | Table | Record ID | Rule | Description |")
            lines.append("|---|---|---|---|---|---|")
            for f in all_findings[:25]:
                sev_icon = "🔴" if f.severity in (Severity.CRITICAL, "CRITICAL") else ("🟠" if f.severity in (Severity.ERROR, "ERROR") else "🟡")
                sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                rec_id_str = f"`{f.record_id}`" if f.record_id else "-"
                clean_msg = f.message.replace("|", "/")
                lines.append(
                    f"| `{f.finding_id}` | {sev_icon} {sev_str} | `{f.table_name}` | {rec_id_str} | `{f.rule_name}` | {clean_msg} |"
                )

            if len(all_findings) > 25:
                lines.append(f"\n*...and {len(all_findings) - 25} more findings omitted for brevity. See JSON/CSV export for complete ledger.*")

        lines.append("")
        return "\n".join(lines)

    def to_html(self) -> str:
        """Generate a self-contained modern HTML audit report dashboard."""
        s = self.summary
        findings_json = []
        for c in s.check_results:
            for f in c.findings:
                findings_json.append(f.to_dict())

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Data Integrity Audit Report - {s.target_name}</title>
  <style>
    :root {{
      --bg-dark: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent-blue: #38bdf8;
      --accent-green: #22c55e;
      --accent-red: #ef4444;
      --accent-amber: #f59e0b;
      --accent-purple: #a855f7;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-dark);
      color: var(--text-main);
      padding: 2rem;
      line-height: 1.5;
    }}
    .container {{ max-width: 1300px; margin: 0 auto; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 1.5rem;
    }}
    h1 {{ font-size: 1.8rem; font-weight: 700; color: #fff; }}
    .badge {{
      display: inline-block;
      padding: 0.35rem 0.8rem;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 600;
    }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
    .badge-error {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
    .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
    .badge-info {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #38bdf8; }}
    .badge-pass {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }}

    .grid-kpi {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 1.25rem;
    }}
    .card-title {{ font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }}
    .card-val {{ font-size: 2.1rem; font-weight: 700; margin-top: 0.5rem; }}
    .health-val {{ color: {('#22c55e' if s.integrity_score >= 90 else ('#f59e0b' if s.integrity_score >= 70 else '#ef4444'))}; }}

    .section-title {{ font-size: 1.3rem; margin: 2rem 0 1rem; color: #fff; display: flex; align-items: center; gap: 0.5rem; }}

    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 2rem;
    }}
    th, td {{ padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--card-border); font-size: 0.9rem; }}
    th {{ background: #182234; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
    tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
    .code-pill {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: #0b1120; padding: 2px 6px; border-radius: 4px; font-size: 0.82rem; }}

    .filter-bar {{
      display: flex;
      gap: 1rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }}
    input, select {{
      background: #0b1120;
      border: 1px solid var(--card-border);
      color: #fff;
      padding: 0.6rem 1rem;
      border-radius: 6px;
      font-size: 0.9rem;
    }}
    input:focus, select:focus {{ outline: none; border-color: var(--accent-blue); }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🛡️ Data Integrity Audit: {s.target_name}</h1>
        <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.25rem;">
          Run ID: <code>{s.run_id}</code> | Time: {s.start_time} | Elapsed: {s.duration_seconds:.3f}s
        </p>
      </div>
      <div>
        <span class="badge {('badge-pass' if s.flagged_records == 0 else ('badge-warning' if s.findings_by_severity.get('CRITICAL',0)==0 and s.findings_by_severity.get('ERROR',0)==0 else 'badge-critical'))}">
          {('AUDIT PASSED' if s.flagged_records == 0 else ('AUDIT WARNINGS' if s.findings_by_severity.get('CRITICAL',0)==0 and s.findings_by_severity.get('ERROR',0)==0 else 'INTEGRITY ISSUES DETECTED'))}
        </span>
      </div>
    </header>

    <div class="grid-kpi">
      <div class="card">
        <div class="card-title">Integrity Health Score</div>
        <div class="card-val health-val">{s.integrity_score:.1f}%</div>
      </div>
      <div class="card">
        <div class="card-title">Total Records Checked</div>
        <div class="card-val" style="color: var(--accent-blue);">{s.total_records:,}</div>
      </div>
      <div class="card">
        <div class="card-title">Flagged Discrepancies</div>
        <div class="card-val" style="color: {('#22c55e' if s.flagged_records == 0 else '#ef4444')};">{s.flagged_records:,}</div>
      </div>
      <div class="card">
        <div class="card-title">Quarantined Records</div>
        <div class="card-val" style="color: var(--accent-amber);">{s.quarantined_records:,}</div>
      </div>
      <div class="card">
        <div class="card-title">Critical / Hash Mismatches</div>
        <div class="card-val" style="color: #f87171;">{s.findings_by_severity.get('CRITICAL', 0)}</div>
      </div>
    </div>

    <h2 class="section-title">🔍 Check Suite Performance</h2>
    <table>
      <thead>
        <tr>
          <th>Check Name</th>
          <th>Type</th>
          <th>Records Inspected</th>
          <th>Findings</th>
          <th>Latency</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {"".join(f'''
        <tr>
          <td><strong>{c.check_name}</strong></td>
          <td><span class="code-pill">{c.check_type.value if hasattr(c.check_type, "value") else c.check_type}</span></td>
          <td>{c.records_inspected:,}</td>
          <td>{len(c.findings)}</td>
          <td>{c.execution_time_ms:.1f}ms</td>
          <td><span class="badge {('badge-pass' if c.passed else 'badge-critical')}">{"PASSED" if c.passed else "FAILED"}</span></td>
        </tr>
        ''' for c in s.check_results)}
      </tbody>
    </table>

    <h2 class="section-title">🚨 Forensic Discrepancy Ledger</h2>
    <div class="filter-bar">
      <input type="text" id="searchInput" placeholder="Search table, rule, or record ID..." oninput="filterFindings()" style="flex: 1; min-width: 250px;">
      <select id="severityFilter" onchange="filterFindings()">
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="ERROR">Error</option>
        <option value="WARNING">Warning</option>
        <option value="INFO">Info</option>
      </select>
    </div>

    <table id="findingsTable">
      <thead>
        <tr>
          <th>ID</th>
          <th>Severity</th>
          <th>Table</th>
          <th>Record ID</th>
          <th>Rule</th>
          <th>Expected Value</th>
          <th>Observed Value</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody id="findingsBody"></tbody>
    </table>
  </div>

  <script>
    const findingsData = {json.dumps(findings_json)};

    function renderTable(items) {{
      const tbody = document.getElementById("findingsBody");
      if (!items || items.length === 0) {{
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #94a3b8; padding: 2rem;">No discrepancies matching current criteria.</td></tr>';
        return;
      }}
      tbody.innerHTML = items.map(f => {{
        const sevClass = f.severity === "CRITICAL" ? "badge-critical" : (f.severity === "ERROR" ? "badge-error" : "badge-warning");
        return `
          <tr>
            <td><span class="code-pill">${{f.finding_id || '-'}}</span></td>
            <td><span class="badge ${{sevClass}}">${{f.severity}}</span></td>
            <td><strong>${{f.table_name}}</strong></td>
            <td><span class="code-pill">${{f.record_id || '-'}}</span></td>
            <td>${{f.rule_name}}</td>
            <td><code style="color: #4ade80;">${{f.expected_value != null ? String(f.expected_value) : '-'}}</code></td>
            <td><code style="color: #f87171;">${{f.actual_value != null ? String(f.actual_value) : '-'}}</code></td>
            <td style="font-size: 0.85rem; color: #cbd5e1;">${{f.message}}</td>
          </tr>
        `;
      }}).join('');
    }}

    function filterFindings() {{
      const q = document.getElementById("searchInput").value.toLowerCase();
      const sev = document.getElementById("severityFilter").value;
      const filtered = findingsData.filter(f => {{
        const matchSev = !sev || f.severity === sev;
        const text = `${{f.table_name}} ${{f.rule_name}} ${{f.record_id || ''}} ${{f.message}}`.toLowerCase();
        const matchQuery = !q || text.includes(q);
        return matchSev && matchQuery;
      }});
      renderTable(filtered);
    }}

    // Initial render
    renderTable(findingsData);
  </script>
</body>
</html>
"""

    def save_reports(self, output_dir: str, base_filename: str = "integrity_audit") -> Dict[str, str]:
        """Save report files (JSON, CSV, MD, HTML) to output directory."""
        os.makedirs(output_dir, exist_ok=True)
        paths = {
            "json": os.path.join(output_dir, f"{base_filename}.json"),
            "csv": os.path.join(output_dir, f"{base_filename}.csv"),
            "markdown": os.path.join(output_dir, f"{base_filename}.md"),
            "html": os.path.join(output_dir, f"{base_filename}.html"),
        }

        with open(paths["json"], "w", encoding="utf-8") as f:
            f.write(self.to_json())

        with open(paths["csv"], "w", encoding="utf-8") as f:
            f.write(self.to_csv())

        with open(paths["markdown"], "w", encoding="utf-8") as f:
            f.write(self.to_markdown())

        with open(paths["html"], "w", encoding="utf-8") as f:
            f.write(self.to_html())

        return paths

// Interactive Data Integrity Dashboard Logic

let currentSummary = null;
let allFindings = [];

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  loadSummary();
  setupEventListeners();
});

function initTabs() {
  const navBtns = document.querySelectorAll(".nav-item");
  const tabPanes = document.querySelectorAll(".tab-pane");

  navBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      navBtns.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const activePane = document.getElementById(`tab-${targetTab}`);
      if (activePane) activePane.classList.add("active");

      if (targetTab === "quarantine") {
        loadQuarantine();
      }
    });
  });
}

function setupEventListeners() {
  document.getElementById("runPipelineBtn").addEventListener("click", runPipeline);
  document.getElementById("findingSearch").addEventListener("input", filterFindings);
  document.getElementById("severitySelect").addEventListener("change", filterFindings);
}

async function loadSummary() {
  try {
    const res = await fetch("/api/summary");
    const data = await res.json();
    currentSummary = data;
    renderSummary(data);
  } catch (err) {
    console.error("Failed to load summary:", err);
  }
}

async function runPipeline() {
  const btn = document.getElementById("runPipelineBtn");
  btn.disabled = true;
  btn.textContent = "⏳ Running Pipeline...";

  try {
    const res = await fetch("/api/run", { method: "POST" });
    const data = await res.json();
    if (data.success) {
      currentSummary = data.summary;
      renderSummary(data.summary);
    }
  } catch (err) {
    console.error("Error executing pipeline:", err);
  } finally {
    btn.disabled = false;
    btn.textContent = "⚡ Run Validation Pipeline";
  }
}

function renderSummary(s) {
  if (!s || !s.run_id) return;

  // Run info header
  document.getElementById("runInfoText").textContent =
    `Run ID: ${s.run_id} | Completed in ${s.duration_seconds.toFixed(2)}s | Target: ${s.target_name}`;

  // Audit badge
  const badge = document.getElementById("auditBadge");
  const critCount = s.findings_by_severity?.CRITICAL || 0;
  const errCount = s.findings_by_severity?.ERROR || 0;

  if (s.flagged_records === 0) {
    badge.className = "badge badge-pass";
    badge.textContent = "HEALTHY (CLEAN)";
  } else if (critCount > 0 || errCount > 0) {
    badge.className = "badge badge-critical";
    badge.textContent = "ANOMALIES DETECTED";
  } else {
    badge.className = "badge badge-warning";
    badge.textContent = "WARNINGS FOUND";
  }

  // KPIs
  document.getElementById("kpiScore").textContent = `${s.integrity_score.toFixed(1)}%`;
  document.getElementById("kpiTotal").textContent = Number(s.total_records).toLocaleString();
  document.getElementById("kpiFlagged").textContent = Number(s.flagged_records).toLocaleString();
  document.getElementById("kpiQuarantined").textContent = Number(s.quarantined_records).toLocaleString();

  // Severity breakdown
  const sevContainer = document.getElementById("severityBars");
  const sevs = s.findings_by_severity || {};
  sevContainer.innerHTML = `
    <div class="severity-row">
      <span>🔴 Critical Issues</span>
      <span class="badge badge-critical">${sevs.CRITICAL || 0}</span>
    </div>
    <div class="severity-row">
      <span>🟠 Hard Errors</span>
      <span class="badge badge-error">${sevs.ERROR || 0}</span>
    </div>
    <div class="severity-row">
      <span>🟡 Warnings</span>
      <span class="badge badge-warning">${sevs.WARNING || 0}</span>
    </div>
    <div class="severity-row">
      <span>🔵 Info / Cosmetic</span>
      <span class="badge badge-info">${sevs.INFO || 0}</span>
    </div>
  `;

  // Table health list
  const tblContainer = document.getElementById("tableHealthList");
  tblContainer.innerHTML = "";
  const tbls = s.table_summaries || {};
  Object.keys(tbls).forEach(name => {
    const t = tbls[name];
    const cleanRatio = t.total_rows > 0 ? ((t.clean_rows / t.total_rows) * 100).toFixed(0) : 100;
    const row = document.createElement("div");
    row.className = "table-health-row";
    row.innerHTML = `
      <div>
        <strong>${name}</strong>
        <div class="text-sm text-muted">${t.total_rows} total rows (${t.flagged_rows} flagged)</div>
      </div>
      <div>
        <span class="badge ${cleanRatio == 100 ? 'badge-pass' : (cleanRatio > 80 ? 'badge-warning' : 'badge-critical')}">
          ${cleanRatio}% Clean
        </span>
      </div>
    `;
    tblContainer.appendChild(row);
  });

  // Extract all findings
  allFindings = [];
  (s.check_results || []).forEach(cr => {
    (cr.findings || []).forEach(f => {
      allFindings.push(f);
    });
  });

  renderFindingsTable(allFindings);
  renderChecksTable(s.check_results || []);
}

function renderFindingsTable(items) {
  const tbody = document.getElementById("findingsTableBody");
  if (!items || items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted" style="padding: 2rem;">No discrepancies found matching criteria.</td></tr>';
    return;
  }

  tbody.innerHTML = items.map(f => {
    const sevClass = f.severity === "CRITICAL" ? "badge-critical" : (f.severity === "ERROR" ? "badge-error" : "badge-warning");
    return `
      <tr>
        <td><span class="code-pill">${f.finding_id || '-'}</span></td>
        <td><span class="badge ${sevClass}">${f.severity}</span></td>
        <td><strong>${f.table_name}</strong></td>
        <td><span class="code-pill">${f.record_id || '-'}</span></td>
        <td>${f.rule_name}</td>
        <td><code class="text-green">${f.expected_value != null ? String(f.expected_value) : '-'}</code></td>
        <td><code class="text-red">${f.actual_value != null ? String(f.actual_value) : '-'}</code></td>
        <td class="text-sm text-muted">${f.message}</td>
      </tr>
    `;
  }).join('');
}

function filterFindings() {
  const query = document.getElementById("findingSearch").value.toLowerCase();
  const sev = document.getElementById("severitySelect").value;

  const filtered = allFindings.filter(f => {
    const matchSev = !sev || f.severity === sev;
    const str = `${f.table_name} ${f.rule_name} ${f.record_id || ''} ${f.message}`.toLowerCase();
    const matchQuery = !query || str.includes(query);
    return matchSev && matchQuery;
  });

  renderFindingsTable(filtered);
}

function renderChecksTable(checks) {
  const tbody = document.getElementById("checksTableBody");
  if (!checks || checks.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No check suites executed.</td></tr>';
    return;
  }

  tbody.innerHTML = checks.map(c => {
    const passClass = c.passed ? "badge-pass" : "badge-critical";
    const passText = c.passed ? "PASSED" : "FAILED";
    return `
      <tr>
        <td><strong>${c.check_name}</strong></td>
        <td><span class="code-pill">${c.check_type}</span></td>
        <td>${Number(c.records_inspected).toLocaleString()}</td>
        <td>${c.findings_count || (c.findings ? c.findings.length : 0)}</td>
        <td>${c.execution_time_ms.toFixed(1)}ms</td>
        <td><span class="badge ${passClass}">${passText}</span></td>
      </tr>
    `;
  }).join('');
}

async function loadQuarantine() {
  try {
    const res = await fetch("/api/quarantine?limit=50");
    const json = await res.json();
    const items = json.data || [];

    document.getElementById("quarantineCountBadge").textContent = `${items.length} Records`;
    const tbody = document.getElementById("quarantineTableBody");

    if (items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted" style="padding: 2rem;">Quarantine store is currently empty.</td></tr>';
      return;
    }

    tbody.innerHTML = items.map(q => {
      const sevClass = q.severity === "CRITICAL" ? "badge-critical" : "badge-error";
      const rules = Array.isArray(q.violated_rules) ? q.violated_rules.join(", ") : q.violated_rules;
      return `
        <tr>
          <td><span class="code-pill">${q.quarantine_id}</span></td>
          <td><strong>${q.source_table}</strong></td>
          <td><span class="code-pill">${q.record_id}</span></td>
          <td><span class="badge ${sevClass}">${q.severity}</span></td>
          <td class="text-sm">${rules}</td>
          <td class="text-sm text-muted">${q.quarantined_at ? q.quarantined_at.replace("T", " ").substring(0, 19) : '-'}</td>
          <td class="text-sm text-muted">${q.reason}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error("Failed to load quarantine records:", err);
  }
}

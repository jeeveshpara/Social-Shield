import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Scan, Finding } from "../types";
import { fetchScans, createScan, getErrorMessage, formatDate, getRiskClass, getStoredUser, clearStoredSession } from "../api";
import "../styles/dashboard.css";

/** Normalise findings to always be a flat array regardless of DB row format. */
function normaliseFindings(findings: unknown): Finding[] {
  if (Array.isArray(findings)) return findings as Finding[];
  if (findings && typeof findings === "object") {
    const obj = findings as Record<string, unknown>;
    // Heuristic scans store { input_type, items: [...] }
    if (Array.isArray(obj.items)) return obj.items as Finding[];
  }
  return [];
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const [currentUser, setCurrentUser] = useState(getStoredUser());
  const [target, setTarget] = useState("");
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    const user = getStoredUser();
    if (!user) {
      navigate("/login");
    } else {
      setCurrentUser(user);
    }
  }, [navigate]);

  const loadScans = useCallback(async () => {
    try {
      setHistoryLoading(true);
      const history = await fetchScans();
      setScans(history);
      setSelectedScanId((cur) => {
        if (cur !== null && history.some((s) => s.id === cur)) return cur;
        return history.length > 0 ? history[0].id : null;
      });
      setError("");
    } catch (err) {
      setError(`Unable to load scan history: ${getErrorMessage(err)}`);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadScans();
  }, [loadScans]);

  const handleSignOut = () => {
    clearStoredSession();
    navigate("/login");
  };

  const handleScan = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!target.trim()) {
      setError("Enter a username or profile URL.");
      return;
    }
    setLoading(true);
    setError("");
    setSuccess("");
    try {
      const scan = await createScan(target);
      setTarget("");
      setSuccess(`Assessment #${scan.id} completed.`);
      await loadScans();
      setSelectedScanId(scan.id);
    } catch (err) {
      setError(`Assessment failed: ${getErrorMessage(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const selectedScan = scans.find((s) => s.id === selectedScanId);
  const totalHighRisk = scans.filter((s) => s.risk_level === "HIGH").length;
  const avgRisk = scans.length
    ? Math.round(scans.reduce((sum, s) => sum + s.risk_score, 0) / scans.length)
    : 0;

  return (
    <div className="dashboard">
      {/* ── Sidebar ────────────────────────────────────────────────────── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="sidebar-icon" aria-hidden="true">🛡️</span>
          <span>SocialShield</span>
        </div>

        <nav className="sidebar-nav" aria-label="Main navigation">
          <a href="/dashboard" className="nav-item active" aria-current="page">
            <span aria-hidden="true">📊</span> Dashboard
          </a>
          <a href="/dashboard" className="nav-item">
            <span aria-hidden="true">🔍</span> Scans
          </a>
          <a href="/dashboard" className="nav-item">
            <span aria-hidden="true">⚠️</span> Threats
          </a>
          <a href="/dashboard" className="nav-item">
            <span aria-hidden="true">⚙️</span> Settings
          </a>
        </nav>

        <div className="sidebar-footer">
          {currentUser && (
            <div style={{ marginBottom: "12px", padding: "8px 12px", background: "rgba(255,255,255,0.03)", borderRadius: "6px", fontSize: "0.8rem", border: "1px solid var(--border)" }}>
              <div style={{ color: "var(--text-secondary)", fontSize: "0.72rem" }}>Logged in as:</div>
              <div style={{ fontWeight: 700, color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "6px" }}>
                <span>{currentUser.role === "admin" ? "👑" : "🔍"}</span>
                <span>{currentUser.username}</span>
                <span style={{ fontSize: "0.68rem", background: "rgba(99, 102, 241, 0.2)", color: "#a5b4fc", padding: "1px 6px", borderRadius: "4px" }}>
                  {currentUser.role}
                </span>
              </div>
            </div>
          )}
          <button
            type="button"
            className="signout-btn"
            onClick={handleSignOut}
          >
            ← Sign out
          </button>
        </div>
      </aside>

      {/* ── Main content ───────────────────────────────────────────────── */}
      <div className="dashboard-main">
        {/* Top bar */}
        <header className="topbar">
          <div>
            <h1 className="topbar-title">Security Dashboard</h1>
            <p className="topbar-sub">Social account threat intelligence & OSINT engine</p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <span className="api-status">
              <span className="status-dot" aria-hidden="true" />
              API Connected
            </span>
          </div>
        </header>

        <main className="dashboard-content">
          {/* ── Stats row ──────────────────────────────────────────────── */}
          <section className="stats-row" aria-label="Overview statistics">
            <div className="stat-card">
              <div className="stat-icon stat-blue" aria-hidden="true">📋</div>
              <div>
                <div className="stat-label">Total Scans</div>
                <div className="stat-value">{scans.length}</div>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon stat-red" aria-hidden="true">🚨</div>
              <div>
                <div className="stat-label">High Risk</div>
                <div className="stat-value">{totalHighRisk}</div>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon stat-yellow" aria-hidden="true">📈</div>
              <div>
                <div className="stat-label">Average Risk</div>
                <div className="stat-value">{avgRisk}<span className="stat-unit">/100</span></div>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon stat-green" aria-hidden="true">✅</div>
              <div>
                <div className="stat-label">Clean Scans</div>
                <div className="stat-value">{scans.filter((s) => s.risk_level === "INFO").length}</div>
              </div>
            </div>
          </section>

          <div className="content-grid">
            {/* ── Left column ─────────────────────────────────────────── */}
            <div className="left-col">
              {/* Scan form */}
              <section className="card scan-form-card">
                <h2 className="card-title">New Security Assessment</h2>
                <p className="card-sub">
                  Enter a username, social profile URL, or any suspicious URL to analyse.
                </p>

                <form className="scan-form" id="scan-form" onSubmit={handleScan}>
                  <div className="input-row">
                    <input
                      id="scan-target-input"
                      type="text"
                      placeholder="e.g. @username or https://suspicious-url.com"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      maxLength={2048}
                      required
                      aria-label="Scan target: username or URL"
                    />
                    <button
                      id="scan-submit-btn"
                      type="submit"
                      className="btn-primary"
                      disabled={loading}
                    >
                      {loading ? (
                        <><span className="spinner" aria-hidden="true" /> Analysing…</>
                      ) : (
                        <><span aria-hidden="true">🔍</span> Analyse</>
                      )}
                    </button>
                  </div>
                  <small className="form-notice">
                    Local heuristic analysis only. Submit only public or
                    authorised data.
                  </small>
                </form>

                {error && (
                  <div className="alert alert-error" role="alert">{error}</div>
                )}
                {success && (
                  <div className="alert alert-success" role="status">{success}</div>
                )}
              </section>

              {/* Scan history */}
              <section className="card history-card">
                <div className="card-header">
                  <h2 className="card-title">Assessment History</h2>
                  <button
                    type="button"
                    id="refresh-history-btn"
                    className="btn-secondary"
                    onClick={() => void loadScans()}
                    disabled={historyLoading}
                  >
                    {historyLoading ? "Loading…" : "↻ Refresh"}
                  </button>
                </div>

                {historyLoading && scans.length === 0 ? (
                  <div className="empty-state">
                    <div className="spinner-large" aria-label="Loading…" />
                    <p>Loading assessments…</p>
                  </div>
                ) : scans.length === 0 ? (
                  <div className="empty-state">
                    <p>No assessments yet. Run your first scan above.</p>
                  </div>
                ) : (
                  <div className="scan-list" role="list">
                    {scans.map((scan) => (
                      <button
                        type="button"
                        role="listitem"
                        key={scan.id}
                        id={`scan-row-${scan.id}`}
                        className={`scan-row${selectedScanId === scan.id ? " selected" : ""}`}
                        onClick={() => setSelectedScanId(scan.id)}
                      >
                        <div className="scan-target">
                          <strong className="scan-target-text">{scan.target}</strong>
                          <span className="scan-meta">
                            {scan.platform} · #{scan.id}
                          </span>
                          <small className="scan-date">{formatDate(scan.created_at)}</small>
                        </div>
                        <div className="scan-risk-col">
                          <span className="scan-score">{scan.risk_score}/100</span>
                          <span className={`risk-badge risk-${getRiskClass(scan.risk_level)}`}>
                            {scan.risk_level}
                          </span>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </section>
            </div>

            {/* ── Right column: findings panel ───────────────────────── */}
            {selectedScan ? (
              <aside className="right-col">
                <section className="card findings-card">
                  <div className="card-header">
                    <div>
                      <h2 className="card-title">Assessment Detail</h2>
                      <p className="card-sub">
                        Scan #{selectedScan.id} · {formatDate(selectedScan.created_at)}
                      </p>
                    </div>
                    <button
                      type="button"
                      id={`open-findings-${selectedScan.id}`}
                      className="btn-secondary"
                      onClick={() => navigate(`/scans/${selectedScan.id}`)}
                    >
                      Full Report →
                    </button>
                  </div>

                  {/* Risk summary */}
                  <div className={`risk-summary risk-bg-${getRiskClass(selectedScan.risk_level)}`}>
                    <div>
                      <div className="risk-label">Risk Score</div>
                      <div className="risk-score-large">
                        {selectedScan.risk_score}
                        <span className="risk-denom">/100</span>
                      </div>
                    </div>
                    <span className={`risk-badge risk-${getRiskClass(selectedScan.risk_level)}`}>
                      {selectedScan.risk_level} RISK
                    </span>
                  </div>

                  {/* Target */}
                  <div className="target-box">
                    <div className="target-label">Target</div>
                    <div className="target-value">{selectedScan.target}</div>
                    {selectedScan.evidence?.username_intel && (
                      <div style={{ marginTop: "6px", fontSize: "0.76rem", color: "var(--cyan)" }}>
                        🔎 OSINT: {selectedScan.evidence.username_intel.footprint?.filter((p) => p.status === "found").length || 0} profiles found · Entropy: {selectedScan.evidence.username_intel.entropy}
                      </div>
                    )}
                    {selectedScan.evidence?.domain_intel && (
                      <div style={{ marginTop: "6px", fontSize: "0.76rem", color: "var(--cyan)" }}>
                        🌐 OSINT: {selectedScan.evidence.domain_intel.rdap?.age_days !== undefined ? `${selectedScan.evidence.domain_intel.rdap.age_days}d domain age` : "Domain analyzed"} · {selectedScan.evidence.domain_intel.dns?.a_records?.length || 0} IP(s)
                      </div>
                    )}
                    {selectedScan.evidence?.url_trace?.is_shortener && (
                      <div style={{ marginTop: "6px", fontSize: "0.76rem", color: "var(--yellow)" }}>
                        🔗 Shortened Link → {selectedScan.evidence.url_trace.final_url}
                      </div>
                    )}
                    <small>Heuristic indicators, not proof of fraud.</small>
                  </div>

                  {/* Findings list (compact) */}
                  <h3 className="findings-heading">Evidence & Indicators</h3>
                  <div className="findings-list">
                    {normaliseFindings(selectedScan.findings)
                      .filter((f) => f.type !== "analysis_metadata")
                      .slice(0, 4)
                      .map((f, i) => (
                        <div
                          key={`${f.code ?? f.type ?? "f"}-${i}`}
                          className="finding-chip"
                        >
                          <div className="finding-chip-header">
                            <span className="finding-code">
                              {(f.code ?? f.type ?? "Finding").replaceAll("_", " ")}
                            </span>
                            <span className={`sev-badge sev-${f.severity ?? "info"}`}>
                              {f.severity ?? "info"}
                            </span>
                          </div>
                          <p className="finding-chip-desc">
                            {f.evidence ?? f.description ?? "—"}
                          </p>
                        </div>
                      ))}
                    {normaliseFindings(selectedScan.findings).filter((f) => f.type !== "analysis_metadata").length > 4 && (
                      <button
                        type="button"
                        className="btn-link"
                        onClick={() => navigate(`/scans/${selectedScan.id}`)}
                      >
                        View all findings →
                      </button>
                    )}
                  </div>
                </section>
              </aside>
            ) : (
              <aside className="right-col">
                <div className="card no-selection-card">
                  <span className="no-sel-icon" aria-hidden="true">🔍</span>
                  <h3>Select a scan</h3>
                  <p>Click any scan from the history list to view its findings here.</p>
                </div>
              </aside>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

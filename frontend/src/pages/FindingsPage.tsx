import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import type { Finding, Scan, OsintEvidence } from "../types";
import { fetchScan, getErrorMessage, formatDate, getRiskClass, getSeverityClass } from "../api";
import "../styles/findings.css";

/** Normalise findings to always be a flat array regardless of DB row format. */
function normaliseFindings(findings: unknown): Finding[] {
  if (Array.isArray(findings)) return findings as Finding[];
  if (findings && typeof findings === "object") {
    const obj = findings as Record<string, unknown>;
    if (Array.isArray(obj.items)) return obj.items as Finding[];
  }
  return [];
}

export default function FindingsPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const scanId = Number(id);
    if (!id || Number.isNaN(scanId)) {
      setError("Invalid scan ID.");
      setLoading(false);
      return;
    }
    fetchScan(scanId)
      .then((data) => setScan(data))
      .catch((err) => setError(getErrorMessage(err)))
      .finally(() => setLoading(false));
  }, [id]);

  const findings: Finding[] = scan
    ? normaliseFindings(scan.findings).filter((f) => f.type !== "analysis_metadata")
    : [];

  const analysisScope = scan
    ? normaliseFindings(scan.findings).find((f) => f.type === "analysis_metadata")?.description
    : undefined;

  const evidence: OsintEvidence | undefined = scan?.evidence;
  const usernameIntel = evidence?.username_intel;
  const domainIntel = evidence?.domain_intel;
  const urlTrace = evidence?.url_trace;
  const metadata = evidence?.metadata;
  const fraudIntel = evidence?.fraud_intel;
  const aiAnalyst = evidence?.ai_analyst;

  return (
    <div className="findings-page">
      {/* ── Animated background ──────────────────────────────────────── */}
      <div className="fp-bg" aria-hidden="true">
        <div className="fp-glow fp-glow-1" />
        <div className="fp-glow fp-glow-2" />
      </div>

      <div className="fp-container">
        {/* Back button */}
        <button
          type="button"
          id="back-to-dashboard"
          className="back-btn"
          onClick={() => navigate("/dashboard")}
        >
          ← Back to Dashboard
        </button>

        {loading && (
          <div className="fp-loading" role="status">
            <div className="spinner-large" aria-label="Loading…" />
            <p>Loading assessment…</p>
          </div>
        )}

        {error && (
          <div className="fp-error" role="alert">
            <strong>Error:</strong> {error}
          </div>
        )}

        {scan && (
          <>
            {/* ── Header ─────────────────────────────────────────────── */}
            <header className="fp-header">
              <div className="fp-header-left">
                <div className="fp-badge">
                  <span aria-hidden="true">🛡️</span> SocialShield OSINT Engine
                </div>
                <h1 className="fp-title">Security Assessment Report</h1>
                <p className="fp-meta">
                  Scan #{scan.id} · {formatDate(scan.created_at)} ·{" "}
                  <span className="fp-platform">{scan.platform}</span>
                </p>
              </div>

              <div
                className={`fp-risk-badge risk-${getRiskClass(scan.risk_level)}`}
                aria-label={`Risk level: ${scan.risk_level}`}
              >
                <div className="fp-risk-score">{scan.risk_score}</div>
                <div className="fp-risk-denom">/100</div>
                <div className="fp-risk-label">{scan.risk_level} RISK</div>
              </div>
            </header>

            {/* ── Target info ─────────────────────────────────────────── */}
            <section className="fp-card fp-target" aria-label="Scan target">
              <div className="fp-card-label">🎯 Assessment Target</div>
              <div className="fp-target-value">{scan.target}</div>
              {analysisScope && (
                <p className="fp-scope">{analysisScope}</p>
              )}
              <small className="fp-disclaimer">
                Risk scores are heuristic indicators based on public open-source intelligence.
              </small>
            </section>

            {/* ── Risk breakdown ──────────────────────────────────────── */}
            <section className="fp-card" aria-label="Risk score breakdown">
              <h2 className="fp-section-title">Risk Breakdown</h2>
              <div className="risk-bar-track" aria-label={`Risk score ${scan.risk_score} out of 100`}>
                <div
                  className={`risk-bar-fill risk-fill-${getRiskClass(scan.risk_level)}`}
                  style={{ width: `${scan.risk_score}%` }}
                />
              </div>
              <div className="risk-bar-labels">
                <span>0</span>
                <span className="rbl-safe">Safe</span>
                <span className="rbl-med">Medium</span>
                <span className="rbl-high">High</span>
                <span>100</span>
              </div>
              {/* Multi-Factor Fraud Risk Dimensions */}
              {fraudIntel?.risk_breakdown && (
                <div style={{ marginTop: "20px" }}>
                  <div style={{ fontSize: "0.82rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
                    Multi-Factor Threat Radar (Sprint 4 Fraud Engine)
                  </div>
                  <div className="radar-grid">
                    <div className="radar-item">
                      <span className="radar-label">OSINT Signals</span>
                      <div className="radar-val-row">
                        <span className="radar-val" style={{ color: "#38bdf8" }}>
                          {fraudIntel.risk_breakdown.dimension_scores.osint}
                        </span>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>/100</span>
                      </div>
                      <div className="radar-bar">
                        <div
                          className="radar-fill"
                          style={{
                            width: `${fraudIntel.risk_breakdown.dimension_scores.osint}%`,
                            background: "#38bdf8",
                          }}
                        />
                      </div>
                    </div>

                    <div className="radar-item">
                      <span className="radar-label">Phishing Risk</span>
                      <div className="radar-val-row">
                        <span className="radar-val" style={{ color: "#f43f5e" }}>
                          {fraudIntel.risk_breakdown.dimension_scores.phishing}
                        </span>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>/100</span>
                      </div>
                      <div className="radar-bar">
                        <div
                          className="radar-fill"
                          style={{
                            width: `${fraudIntel.risk_breakdown.dimension_scores.phishing}%`,
                            background: "#f43f5e",
                          }}
                        />
                      </div>
                    </div>

                    <div className="radar-item">
                      <span className="radar-label">Scam Indicators</span>
                      <div className="radar-val-row">
                        <span className="radar-val" style={{ color: "#f59e0b" }}>
                          {fraudIntel.risk_breakdown.dimension_scores.scam}
                        </span>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>/100</span>
                      </div>
                      <div className="radar-bar">
                        <div
                          className="radar-fill"
                          style={{
                            width: `${fraudIntel.risk_breakdown.dimension_scores.scam}%`,
                            background: "#f59e0b",
                          }}
                        />
                      </div>
                    </div>

                    <div className="radar-item">
                      <span className="radar-label">Impersonation</span>
                      <div className="radar-val-row">
                        <span className="radar-val" style={{ color: "#a855f7" }}>
                          {fraudIntel.risk_breakdown.dimension_scores.impersonation}
                        </span>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>/100</span>
                      </div>
                      <div className="radar-bar">
                        <div
                          className="radar-fill"
                          style={{
                            width: `${fraudIntel.risk_breakdown.dimension_scores.impersonation}%`,
                            background: "#a855f7",
                          }}
                        />
                      </div>
                    </div>
                  </div>

                  {fraudIntel.risk_breakdown.risk_factors.length > 0 && (
                    <div style={{ marginTop: "14px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                      {fraudIntel.risk_breakdown.risk_factors.map((factor, idx) => (
                        <span
                          key={idx}
                          style={{
                            fontSize: "0.75rem",
                            background: "rgba(239, 68, 68, 0.12)",
                            color: "#fca5a5",
                            padding: "3px 8px",
                            borderRadius: "4px",
                            border: "1px solid rgba(239, 68, 68, 0.25)",
                          }}
                        >
                          ⚠️ {factor}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </section>

            {/* ── Sprint 5: AI Security Analyst Report ────────────────── */}
            {aiAnalyst && (
              <section className="ai-analyst-section" aria-label="AI Security Analyst Report">
                <div className="ai-analyst-card">
                  <div className="ai-header-bar">
                    <div className="ai-analyst-badge">
                      <span aria-hidden="true">🤖</span> AI Security Analyst
                    </div>
                    <span className="ai-engine-tag">{aiAnalyst.generated_by}</span>
                  </div>

                  <p className="ai-summary-text">{aiAnalyst.executive_summary}</p>

                  <div className="ai-grid-two">
                    {/* Threat Actor Profile */}
                    <div className="ai-subcard">
                      <div className="ai-subcard-title">
                        <span>🎯</span> Threat Actor Profile
                      </div>
                      <div className="actor-pill-list">
                        <div className="actor-pill-row">
                          <span className="actor-label">Estimated Intent:</span>
                          <span className="actor-val">{aiAnalyst.threat_actor_profile.intent}</span>
                        </div>
                        <div className="actor-pill-row">
                          <span className="actor-label">Sophistication:</span>
                          <span
                            className="actor-val"
                            style={{
                              color:
                                aiAnalyst.threat_actor_profile.sophistication === "Advanced"
                                  ? "#f43f5e"
                                  : aiAnalyst.threat_actor_profile.sophistication === "Moderate"
                                  ? "#f59e0b"
                                  : "#10b981",
                            }}
                          >
                            {aiAnalyst.threat_actor_profile.sophistication}
                          </span>
                        </div>
                        <div className="actor-pill-row">
                          <span className="actor-label">Target Demographic:</span>
                          <span className="actor-val">{aiAnalyst.threat_actor_profile.target_demographic}</span>
                        </div>
                      </div>
                    </div>

                    {/* MITRE ATT&CK Matrix */}
                    <div className="ai-subcard">
                      <div className="ai-subcard-title">
                        <span>🛡️</span> MITRE ATT&CK® Techniques
                      </div>
                      {aiAnalyst.mitre_attack && aiAnalyst.mitre_attack.length > 0 ? (
                        <div className="mitre-badge-list">
                          {aiAnalyst.mitre_attack.map((m) => (
                            <div key={m.id} className="mitre-badge-item">
                              <div className="mitre-badge-top">
                                <span className="mitre-id">{m.id} {m.name}</span>
                                <span className="mitre-tactic">{m.tactic}</span>
                              </div>
                              <div className="mitre-desc">{m.description}</div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ fontSize: "0.82rem", color: "var(--text-secondary)" }}>
                          No offensive techniques mapped for baseline low-risk profile.
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Evidence-Based Synthesis */}
                  {aiAnalyst.evidence_synthesis && aiAnalyst.evidence_synthesis.length > 0 && (
                    <div style={{ marginTop: "16px" }}>
                      <div className="ai-subcard-title">
                        <span>🔍</span> Evidence-Based Telemetry Correlation
                      </div>
                      <ul className="ai-bullets-list">
                        {aiAnalyst.evidence_synthesis.map((bullet, idx) => (
                          <li key={idx} className="ai-bullet-item">
                            <span className="ai-bullet-icon">▸</span>
                            <span>{bullet}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Containment Steps */}
                  {aiAnalyst.containment_steps && aiAnalyst.containment_steps.length > 0 && (
                    <div className="containment-box">
                      <div className="containment-title">
                        <span>🚨</span> Immediate Containment & Incident Response
                      </div>
                      <ul className="ai-bullets-list">
                        {aiAnalyst.containment_steps.map((step, idx) => (
                          <li key={idx} className="ai-bullet-item" style={{ color: "#fecaca" }}>
                            <span style={{ color: "#f87171" }}>⚡</span>
                            <span>{step}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </section>
            )}

            {/* ── Sprint 3: OSINT Intelligence Deep-Dive ──────────────── */}
            <section className="fp-osint-section" aria-label="OSINT Intelligence">
              <h2 className="fp-section-title">
                OSINT Intelligence & Telemetry
                <span className="fp-count">Sprint 3 Engine</span>
              </h2>

              <div className="fp-osint-grid two-col">
                {/* 1. Username OSINT (if available) */}
                {usernameIntel && (
                  <div className="fp-osint-card">
                    <div className="fp-osint-title">
                      <span>👤</span> Username Profiling
                      <span className="fp-osint-badge-chip">Entropy: {usernameIntel.entropy}</span>
                    </div>

                    <div className="meta-rows">
                      <div className="meta-row">
                        <span className="meta-key">Target Handle:</span>
                        <span className="meta-val">@{usernameIntel.username}</span>
                      </div>
                      <div className="meta-row">
                        <span className="meta-key">Shannon Entropy:</span>
                        <span className="meta-val">{usernameIntel.entropy} bits/char</span>
                      </div>
                      {usernameIntel.homoglyphs && usernameIntel.homoglyphs.length > 0 && (
                        <div className="meta-row">
                          <span className="meta-key" style={{ color: "var(--red)" }}>Homoglyphs:</span>
                          <span className="meta-val" style={{ color: "var(--red)" }}>
                            {usernameIntel.homoglyphs.map((h) => `'${h.char}' -> ${h.mimics}`).join(", ")}
                          </span>
                        </div>
                      )}
                      {usernameIntel.impersonation_terms && usernameIntel.impersonation_terms.length > 0 && (
                        <div className="meta-row">
                          <span className="meta-key" style={{ color: "var(--yellow)" }}>Authority Terms:</span>
                          <span className="meta-val" style={{ color: "var(--yellow)" }}>
                            {usernameIntel.impersonation_terms.join(", ")}
                          </span>
                        </div>
                      )}
                    </div>

                    {usernameIntel.footprint && usernameIntel.footprint.length > 0 && (
                      <div style={{ marginTop: "16px" }}>
                        <div className="fp-card-label">Cross-Platform Footprint Probe:</div>
                        <div className="footprint-grid">
                          {usernameIntel.footprint.map((p) => {
                            const isFound = p.status === "found";
                            return (
                              <a
                                key={p.platform}
                                href={isFound && p.profile_url ? p.profile_url : "#"}
                                target={isFound ? "_blank" : undefined}
                                rel={isFound ? "noopener noreferrer" : undefined}
                                className={`footprint-item ${p.status}`}
                                title={isFound ? `View public profile on ${p.platform}` : `${p.platform}: ${p.status}`}
                              >
                                <span className="footprint-name">{p.platform}</span>
                                <span className="footprint-status">
                                  {isFound ? "✓ Found" : p.status === "not_found" ? "✗ None" : p.status}
                                </span>
                              </a>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 2. Domain & DNS Intelligence (if available) */}
                {domainIntel && (
                  <div className="fp-osint-card">
                    <div className="fp-osint-title">
                      <span>🌐</span> Domain & DNS Intelligence
                      <span className="fp-osint-badge-chip">DoH + RDAP</span>
                    </div>

                    <div className="meta-rows">
                      <div className="meta-row">
                        <span className="meta-key">Hostname:</span>
                        <span className="meta-val">{domainIntel.hostname}</span>
                      </div>
                      <div className="meta-row">
                        <span className="meta-key">Apex Domain:</span>
                        <span className="meta-val">{domainIntel.apex_domain}</span>
                      </div>
                      {domainIntel.rdap && domainIntel.rdap.age_days !== undefined && (
                        <div className="meta-row">
                          <span className="meta-key">Domain Age:</span>
                          <span
                            className="meta-val"
                            style={{
                              color:
                                domainIntel.rdap.age_days < 30
                                  ? "var(--red)"
                                  : domainIntel.rdap.age_days < 90
                                  ? "var(--yellow)"
                                  : "var(--green)",
                            }}
                          >
                            {domainIntel.rdap.age_days} days
                            {domainIntel.rdap.age_days < 30 ? " (🚨 NEW)" : ""}
                          </span>
                        </div>
                      )}
                      {domainIntel.rdap?.registrar && (
                        <div className="meta-row">
                          <span className="meta-key">Registrar:</span>
                          <span className="meta-val">{domainIntel.rdap.registrar}</span>
                        </div>
                      )}
                    </div>

                    <div style={{ marginTop: "12px" }}>
                      <div className="fp-card-label">DNS Record Posture:</div>
                      <div className="dns-tags">
                        {domainIntel.dns.a_records && domainIntel.dns.a_records.length > 0 ? (
                          <span className="dns-tag valid">
                            A: {domainIntel.dns.a_records.slice(0, 2).join(", ")}
                          </span>
                        ) : (
                          <span className="dns-tag missing">A: No Records</span>
                        )}

                        {domainIntel.dns.mx_records && domainIntel.dns.mx_records.length > 0 ? (
                          <span className="dns-tag valid">MX: Configured</span>
                        ) : (
                          <span className="dns-tag missing">MX: None (No Mail)</span>
                        )}

                        {domainIntel.dns.spf_records && domainIntel.dns.spf_records.length > 0 ? (
                          <span className="dns-tag valid">SPF: Protected</span>
                        ) : (
                          <span className="dns-tag missing">SPF: Missing</span>
                        )}

                        {domainIntel.dns.dmarc_records && domainIntel.dns.dmarc_records.length > 0 ? (
                          <span className="dns-tag valid">DMARC: Protected</span>
                        ) : (
                          <span className="dns-tag missing">DMARC: Missing</span>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* 3. URL Unshortening & Redirection Chain */}
                {urlTrace && (
                  <div className="fp-osint-card">
                    <div className="fp-osint-title">
                      <span>🔗</span> Redirection & Threat Feeds
                      {urlTrace.is_shortener && <span className="fp-osint-badge-chip">Shortener</span>}
                    </div>

                    <div className="meta-rows">
                      <div className="meta-row">
                        <span className="meta-key">Resolved Dest:</span>
                        <span className="meta-val" style={{ maxWidth: "220px" }}>
                          {urlTrace.final_url}
                        </span>
                      </div>
                      {urlTrace.reputation && (
                        <div className="meta-row">
                          <span className="meta-key">Public Threat Feed:</span>
                          <span
                            className="meta-val"
                            style={{
                              color:
                                urlTrace.reputation.status === "matched"
                                  ? "var(--red)"
                                  : "var(--text-secondary)",
                            }}
                          >
                            {urlTrace.reputation.provider || "URLhaus / PhishTank"} (
                            {urlTrace.reputation.status})
                          </span>
                        </div>
                      )}
                    </div>

                    {urlTrace.redirect_chain && urlTrace.redirect_chain.length > 1 && (
                      <div style={{ marginTop: "12px" }}>
                        <div className="fp-card-label">Hop Sequence ({urlTrace.redirect_chain.length} hops):</div>
                        <div className="redirect-chain-flow">
                          {urlTrace.redirect_chain.map((hop) => (
                            <div key={hop.hop} className="redirect-step">
                              <span className="hop-num">#{hop.hop}</span>
                              <span
                                className={`hop-status ${hop.status_code >= 300 && hop.status_code < 400 ? "redirect" : "ok"}`}
                              >
                                {hop.status_code}
                              </span>
                              <span className="hop-url" title={hop.url}>
                                {hop.url}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 4. Public Web Metadata (OpenGraph / HTML) */}
                {metadata && (metadata.title || metadata.description) && (
                  <div className="fp-osint-card">
                    <div className="fp-osint-title">
                      <span>📑</span> Public Page Metadata
                      <span className="fp-osint-badge-chip">OpenGraph</span>
                    </div>

                    <div className="meta-rows">
                      {metadata.title && (
                        <div className="meta-row">
                          <span className="meta-key">Page Title:</span>
                          <span className="meta-val">{metadata.title}</span>
                        </div>
                      )}
                      {metadata.og_site_name && (
                        <div className="meta-row">
                          <span className="meta-key">Site Name:</span>
                          <span className="meta-val">{metadata.og_site_name}</span>
                        </div>
                      )}
                      {metadata.canonical_url && (
                        <div className="meta-row">
                          <span className="meta-key">Canonical:</span>
                          <span className="meta-val">{metadata.canonical_url}</span>
                        </div>
                      )}
                      {metadata.description && (
                        <div style={{ marginTop: "8px", fontSize: "0.82rem", color: "var(--text-secondary)" }}>
                          <strong>Meta Description:</strong> {metadata.description}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </section>

            {/* ── Findings list ───────────────────────────────────────── */}
            <section aria-label="Evidence and recommendations">
              <h2 className="fp-section-title">
                Security Evidence & Risk Indicators
                <span className="fp-count">{findings.length} finding{findings.length !== 1 ? "s" : ""}</span>
              </h2>

              {findings.length === 0 ? (
                <div className="fp-card fp-empty">
                  <span aria-hidden="true">✅</span>
                  <p>No risk indicators generated for this target.</p>
                </div>
              ) : (
                <div className="fp-findings-grid">
                  {findings.map((f, i) => (
                    <article
                      key={`${f.code ?? f.type ?? "finding"}-${i}`}
                      className={`fp-finding-card ${getSeverityClass(f.severity)}-border`}
                    >
                      <div className="fp-finding-header">
                        <h3 className="fp-finding-code">
                          {(f.code ?? f.type ?? "Finding").replaceAll("_", " ")}
                        </h3>
                        <div className="fp-finding-meta">
                          {typeof f.points === "number" && (
                            <span className="fp-points">+{f.points} pts</span>
                          )}
                          <span className={`fp-sev-badge sev-${f.severity ?? "info"}`}>
                            {f.severity ?? "info"}
                          </span>
                        </div>
                      </div>

                      <p className="fp-finding-evidence">
                        {f.evidence ?? f.description ?? "No evidence description provided."}
                      </p>

                      {f.recommendation && (
                        <div className="fp-recommendation">
                          <div className="fp-rec-label">
                            <span aria-hidden="true">💡</span> Recommended action
                          </div>
                          <p>{f.recommendation}</p>
                        </div>
                      )}
                    </article>
                  ))}
                </div>
              )}
            </section>

            {/* ── Forensics & Raw Evidence Storage Inspector ─────────── */}
            {evidence && Object.keys(evidence).length > 0 && (
              <details className="forensics-details">
                <summary className="forensics-summary">
                  <span>🔬 Forensic OSINT Telemetry Inspector (Raw Evidence Storage)</span>
                  <span style={{ fontSize: "0.8rem", color: "var(--cyan)" }}>Expand JSON ▾</span>
                </summary>
                <pre className="forensics-json">
                  {JSON.stringify(evidence, null, 2)}
                </pre>
              </details>
            )}

            {/* ── Footer disclaimer ───────────────────────────────────── */}
            <footer className="fp-footer">
              <p>
                SocialShield operates on a zero-budget, defensive intelligence principle.
                All telemetry was extracted from open public endpoints, RFC standard protocols (DoH, RDAP),
                and threat research feeds. No accounts were breached and no fees or private access were incurred.
              </p>
              <p className="fp-footer-brand">
                SocialShield v0.3.0 · Sprint 3 OSINT Engine Complete
              </p>
            </footer>
          </>
        )}
      </div>
    </div>
  );
}

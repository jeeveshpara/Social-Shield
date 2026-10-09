import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { loginUser, getErrorMessage } from "../api";
import "../styles/login.css";

export default function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("Admin@12345");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");

    if (!username.trim() || !password.trim()) {
      setError("Please enter your username and password.");
      return;
    }

    setLoading(true);
    try {
      await loginUser(username.trim(), password);
      navigate("/dashboard");
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handleQuickFill = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
    setError("");
  };

  return (
    <div className="login-page">
      {/* Animated background blobs */}
      <div className="blob blob-1" aria-hidden="true" />
      <div className="blob blob-2" aria-hidden="true" />

      <div className="login-card" role="main">
        <div className="login-logo">
          <span className="shield-icon" aria-hidden="true">🛡️</span>
          <h1>SocialShield</h1>
          <p>Defensive Cyber Intelligence Platform</p>
        </div>

        <form className="login-form" onSubmit={handleSubmit} noValidate>
          <div className="field-group">
            <label htmlFor="login-username">Username</label>
            <input
              id="login-username"
              type="text"
              autoComplete="username"
              placeholder="e.g. admin or analyst"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              aria-required="true"
            />
          </div>

          <div className="field-group">
            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              type="password"
              autoComplete="current-password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              aria-required="true"
            />
          </div>

          {error && (
            <div className="login-error" role="alert">
              {error}
            </div>
          )}

          <button
            id="login-submit"
            type="submit"
            className="login-btn"
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner" aria-hidden="true" />
                Signing in…
              </>
            ) : (
              "Sign in with JWT Auth"
            )}
          </button>
        </form>

        {/* Quick Demo Credentials for Convenience */}
        <div style={{ marginTop: "20px", paddingTop: "16px", borderTop: "1px solid var(--border)", fontSize: "0.8rem", color: "var(--text-secondary)" }}>
          <div style={{ fontWeight: 600, marginBottom: "8px" }}>Sprint 6 Seeded Credentials:</div>
          <div style={{ display: "flex", gap: "8px", justifyContent: "center" }}>
            <button
              type="button"
              onClick={() => handleQuickFill("admin", "Admin@12345")}
              style={{
                background: "rgba(59, 130, 246, 0.15)",
                border: "1px solid rgba(59, 130, 246, 0.3)",
                color: "#93c5fd",
                padding: "4px 8px",
                borderRadius: "4px",
                cursor: "pointer",
                fontSize: "0.75rem",
              }}
            >
              👑 Admin (Full Access)
            </button>
            <button
              type="button"
              onClick={() => handleQuickFill("analyst", "Analyst@12345")}
              style={{
                background: "rgba(168, 85, 247, 0.15)",
                border: "1px solid rgba(168, 85, 247, 0.3)",
                color: "#d8b4fe",
                padding: "4px 8px",
                borderRadius: "4px",
                cursor: "pointer",
                fontSize: "0.75rem",
              }}
            >
              🔍 Analyst (Operator)
            </button>
          </div>
        </div>

        <p className="login-notice">
          🔒 Sprint 6 Security Hardening: JWT Bearer Auth & RBAC Active.
        </p>
      </div>
    </div>
  );
}

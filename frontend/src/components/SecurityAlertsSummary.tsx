import React from "react";
import { ShieldX, Clock, AlertOctagon } from "lucide-react";
import { SecuritySummary } from "../types/api";

interface SecurityAlertsSummaryProps {
  summary: SecuritySummary | null;
}

export const SecurityAlertsSummary: React.FC<SecurityAlertsSummaryProps> = ({ summary }) => {
  return (
    <div className="glass-card" style={{ padding: "1.25rem", marginBottom: "1.5rem" }}>
      <div style={{ marginBottom: "1rem" }}>
        <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Threat Intelligence &amp; Anomaly Summary</h2>
        <p style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
          Defensive enforcement from Member 1's Blocklist, Token Bucket Rate Limiter, and Query Inspector
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "1rem" }}>
        
        {/* Blocklist Card */}
        <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(244, 63, 94, 0.2)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
            <ShieldX size={18} color="var(--accent-rose)" />
            <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-primary)" }}>Domain Blocklist</span>
          </div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--accent-rose)" }}>
            {summary?.blocked_queries ?? 0}
          </div>
          <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
            Queries matched against malicious domains or subdomains and returned REFUSED.
          </p>
        </div>

        {/* Rate Limiter Card */}
        <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(245, 158, 11, 0.2)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
            <Clock size={18} color="var(--accent-amber)" />
            <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-primary)" }}>Token Bucket Rate Limiter</span>
          </div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--accent-amber)" }}>
            {summary?.rate_limited_queries ?? 0}
          </div>
          <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
            Excessive query bursts throttled per client IP without crashing the resolver.
          </p>
        </div>

        {/* Inspector Card */}
        <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(239, 68, 68, 0.3)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
            <AlertOctagon size={18} color="#ef4444" />
            <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-primary)" }}>Query Anomaly Inspector</span>
          </div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "#ef4444" }}>
            {summary?.suspicious_queries ?? 0}
          </div>
          <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
            Tunneling payloads (&gt;253 chars), RFC label length (&gt;63 chars), or flood indicators.
          </p>
        </div>

      </div>
    </div>
  );
};

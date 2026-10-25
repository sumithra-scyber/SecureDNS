import React from "react";
import { ShieldCheck, RefreshCw, Database, Activity, Sparkles } from "lucide-react";
import { HealthResponse } from "../types/api";

interface HeaderProps {
  health: HealthResponse | null;
  isLoading: boolean;
  onRefresh: () => void;
  autoRefreshInterval: number;
  onAutoRefreshChange: (interval: number) => void;
  onSeedDemo: () => void;
  isSeeding: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  isLoading,
  onRefresh,
  autoRefreshInterval,
  onAutoRefreshChange,
  onSeedDemo,
  isSeeding,
}) => {
  const isConnected = health?.database === "connected";
  const queueStats = health?.ingestion;

  return (
    <header className="glass-card" style={{ padding: "1rem 1.5rem", marginBottom: "1.5rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
        
        {/* Brand & Title */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.85rem" }}>
          <div style={{
            background: "linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)",
            padding: "0.6rem",
            borderRadius: "10px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 0 15px rgba(56, 189, 248, 0.4)"
          }}>
            <ShieldCheck size={28} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
              <h1 style={{ fontSize: "1.35rem", fontWeight: 700, letterSpacing: "-0.02em" }}>SecureDNS</h1>
              <span className="badge badge-info font-mono">v1.0 • Member 2</span>
            </div>
            <p style={{ fontSize: "0.8rem", color: "var(--text-secondary)", marginTop: "2px" }}>
              High-Performance DNS Resolver &amp; Threat Intelligence Monitoring Console
            </p>
          </div>
        </div>

        {/* Telemetry Status Pills & Actions */}
        <div style={{ display: "flex", alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
          
          {/* DB Status */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", background: "rgba(15, 23, 42, 0.6)", padding: "0.4rem 0.8rem", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
            <Database size={16} color={isConnected ? "var(--accent-emerald)" : "var(--accent-rose)"} />
            <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>Database:</span>
            <span style={{ fontSize: "0.8rem", fontWeight: 600, color: isConnected ? "var(--accent-emerald)" : "var(--accent-rose)" }}>
              {isConnected ? "Connected" : "Disconnected"}
            </span>
          </div>

          {/* Ingestion Worker Status */}
          {queueStats && (
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", background: "rgba(15, 23, 42, 0.6)", padding: "0.4rem 0.8rem", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
              <Activity size={16} color="var(--accent-cyan)" />
              <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>Buffer:</span>
              <span className="font-mono" style={{ fontSize: "0.8rem", fontWeight: 600, color: "var(--text-primary)" }}>
                {queueStats.queue_current_size ?? 0} queued • {queueStats.total_persisted ?? 0} written
              </span>
            </div>
          )}

          {/* Auto refresh dropdown */}
          <select
            value={autoRefreshInterval}
            onChange={(e) => onAutoRefreshChange(Number(e.target.value))}
            style={{ fontSize: "0.8rem", padding: "0.4rem 0.6rem" }}
            title="Auto-refresh interval"
          >
            <option value={0}>Auto: Off</option>
            <option value={3000}>Auto: 3s</option>
            <option value={5000}>Auto: 5s</option>
            <option value={10000}>Auto: 10s</option>
          </select>

          {/* Manual Refresh Button */}
          <button
            onClick={onRefresh}
            className="btn btn-secondary"
            disabled={isLoading}
            style={{ padding: "0.4rem 0.8rem", fontSize: "0.8rem" }}
            title="Refresh dashboard metrics"
          >
            <RefreshCw size={14} className={isLoading ? "spin-icon" : ""} />
            Refresh
          </button>

          {/* Seed Demo Data Button */}
          <button
            onClick={onSeedDemo}
            className="btn btn-primary"
            disabled={isSeeding}
            style={{ padding: "0.4rem 0.85rem", fontSize: "0.8rem" }}
            title="Inject synthetic test events for demonstration"
          >
            <Sparkles size={14} />
            {isSeeding ? "Seeding..." : "Seed Demo Data"}
          </button>
        </div>

      </div>
    </header>
  );
};

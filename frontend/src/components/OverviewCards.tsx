import React from "react";
import { Globe, ShieldAlert, Zap, Layers, AlertTriangle } from "lucide-react";
import { OverviewStats } from "../types/api";

interface OverviewCardsProps {
  stats: OverviewStats | null;
  isLoading: boolean;
}

export const OverviewCards: React.FC<OverviewCardsProps> = ({ stats, isLoading }) => {
  if (isLoading && !stats) {
    return (
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="glass-card" style={{ padding: "1.25rem", minHeight: "110px", opacity: 0.5 }}>
            <div style={{ background: "rgba(255,255,255,0.05)", height: "20px", width: "40%", borderRadius: "4px", marginBottom: "1rem" }} />
            <div style={{ background: "rgba(255,255,255,0.08)", height: "30px", width: "60%", borderRadius: "4px" }} />
          </div>
        ))}
      </div>
    );
  }

  const cards = [
    {
      title: "Total DNS Queries",
      value: (stats?.total_queries ?? 0).toLocaleString(),
      subtext: `${stats?.queries_per_second ?? 0} QPS average`,
      icon: <Globe size={20} color="var(--accent-cyan)" />,
      borderColor: "rgba(6, 182, 212, 0.4)",
    },
    {
      title: "Blocked Queries",
      value: (stats?.blocked_queries ?? 0).toLocaleString(),
      subtext: `${stats?.total_queries ? ((stats.blocked_queries / stats.total_queries) * 100).toFixed(1) : 0}% block rate`,
      icon: <ShieldAlert size={20} color="var(--accent-rose)" />,
      borderColor: "rgba(244, 63, 94, 0.4)",
    },
    {
      title: "Security Threats",
      value: (stats?.security_incidents_total ?? 0).toLocaleString(),
      subtext: `${stats?.suspicious_queries ?? 0} flagged • ${stats?.rate_limited_queries ?? 0} rate-limited`,
      icon: <AlertTriangle size={20} color="var(--accent-amber)" />,
      borderColor: "rgba(245, 158, 11, 0.4)",
    },
    {
      title: "Cache Hit Rate",
      value: `${stats?.cache_hit_rate_pct ?? 0}%`,
      subtext: `${stats?.cache_hits ?? 0} hits / ${stats?.cache_misses ?? 0} misses`,
      icon: <Zap size={20} color="var(--accent-emerald)" />,
      borderColor: "rgba(16, 185, 129, 0.4)",
    },
    {
      title: "Total Tracked Events",
      value: (stats?.total_events ?? 0).toLocaleString(),
      subtext: `${stats?.upstream_failures ?? 0} upstream errors`,
      icon: <Layers size={20} color="var(--accent-purple)" />,
      borderColor: "rgba(139, 92, 246, 0.4)",
    },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
      {cards.map((card, idx) => (
        <div key={idx} className="glass-card" style={{ padding: "1.15rem 1.25rem", borderLeft: `3px solid ${card.borderColor}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem" }}>
            <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)", fontWeight: 500 }}>{card.title}</span>
            <div style={{ background: "rgba(15, 23, 42, 0.8)", padding: "0.4rem", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
              {card.icon}
            </div>
          </div>
          <div style={{ fontSize: "1.65rem", fontWeight: 700, letterSpacing: "-0.03em", color: "var(--text-primary)" }}>
            {card.value}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
            {card.subtext}
          </div>
        </div>
      ))}
    </div>
  );
};

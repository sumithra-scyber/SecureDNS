import React from "react";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { Doughnut } from "react-chartjs-2";
import { EventDistributionItem } from "../types/api";

ChartJS.register(ArcElement, Tooltip, Legend);

interface EventDistributionChartProps {
  distribution: EventDistributionItem[];
}

const COLOR_MAP: Record<string, string> = {
  query_received: "#06b6d4",
  cache_hit: "#10b981",
  cache_miss: "#64748b",
  blocked_request: "#f43f5e",
  rate_limited: "#f59e0b",
  suspicious_activity: "#ef4444",
  upstream_success: "#3b82f6",
  upstream_failure: "#dc2626",
  server_start: "#8b5cf6",
  server_stop: "#a855f7",
};

export const EventDistributionChart: React.FC<EventDistributionChartProps> = ({ distribution }) => {
  const labels = distribution.map((d) => d.event_type.replace("_", " ").toUpperCase());
  const values = distribution.map((d) => d.count);
  const colors = distribution.map((d) => COLOR_MAP[d.event_type] || "#94a3b8");

  const data = {
    labels,
    datasets: [
      {
        data: values,
        backgroundColor: colors,
        borderColor: "rgba(15, 23, 42, 0.9)",
        borderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "right" as const,
        labels: {
          color: "#94a3b8",
          font: { family: "'Inter', sans-serif", size: 10 },
          boxWidth: 10,
          padding: 8,
        },
      },
      tooltip: {
        backgroundColor: "rgba(15, 23, 42, 0.95)",
        titleColor: "#f8fafc",
        bodyColor: "#cbd5e1",
      },
    },
    cutout: "68%",
  };

  return (
    <div className="glass-card" style={{ padding: "1.25rem", height: "350px", display: "flex", flexDirection: "column" }}>
      <div style={{ marginBottom: "0.5rem" }}>
        <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Event Class Distribution</h2>
        <p style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>Categorization of DNS traffic &amp; security telemetry</p>
      </div>
      <div style={{ flex: 1, minHeight: 0, position: "relative" }}>
        {distribution.length === 0 ? (
          <div style={{ display: "flex", height: "100%", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: "0.85rem" }}>
            No events recorded in this window
          </div>
        ) : (
          <Doughnut data={data} options={options} />
        )}
      </div>
    </div>
  );
};

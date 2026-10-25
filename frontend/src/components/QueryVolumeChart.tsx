import React from "react";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import { Line } from "react-chartjs-2";
import { QueryVolumePoint } from "../types/api";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface QueryVolumeChartProps {
  series: QueryVolumePoint[];
  hours: number;
  onHoursChange: (hours: number) => void;
}

export const QueryVolumeChart: React.FC<QueryVolumeChartProps> = ({
  series,
  hours,
  onHoursChange,
}) => {
  const labels = series.map((pt) => {
    const d = new Date(pt.timestamp);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  });

  const data = {
    labels,
    datasets: [
      {
        label: "Queries Received",
        data: series.map((pt) => pt.queries),
        borderColor: "#06b6d4",
        backgroundColor: "rgba(6, 182, 212, 0.15)",
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 2,
        pointHoverRadius: 5,
      },
      {
        label: "Blocked Requests",
        data: series.map((pt) => pt.blocked),
        borderColor: "#f43f5e",
        backgroundColor: "rgba(244, 63, 94, 0.15)",
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 2,
        pointHoverRadius: 5,
      },
      {
        label: "Cache Hits",
        data: series.map((pt) => pt.cache_hits),
        borderColor: "#10b981",
        backgroundColor: "transparent",
        tension: 0.35,
        borderWidth: 1.5,
        borderDash: [4, 4],
        pointRadius: 1,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "top" as const,
        labels: {
          color: "#94a3b8",
          font: { family: "'Inter', sans-serif", size: 11 },
          usePointStyle: true,
          boxWidth: 8,
        },
      },
      tooltip: {
        backgroundColor: "rgba(15, 23, 42, 0.95)",
        titleColor: "#f8fafc",
        bodyColor: "#cbd5e1",
        borderColor: "rgba(148, 163, 184, 0.2)",
        borderWidth: 1,
        padding: 10,
        boxPadding: 4,
      },
    },
    scales: {
      x: {
        grid: { color: "rgba(148, 163, 184, 0.06)" },
        ticks: { color: "#64748b", font: { size: 10 } },
      },
      y: {
        grid: { color: "rgba(148, 163, 184, 0.06)" },
        ticks: { color: "#64748b", font: { size: 10 } },
        beginAtZero: true,
      },
    },
  };

  return (
    <div className="glass-card" style={{ padding: "1.25rem", height: "350px", display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
        <div>
          <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>DNS Query Volume &amp; Security Timeline</h2>
          <p style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>Hourly resolution breakdown over selected window</p>
        </div>
        <div style={{ display: "flex", gap: "0.4rem" }}>
          {[6, 12, 24, 48].map((h) => (
            <button
              key={h}
              className={`btn ${hours === h ? "btn-primary" : "btn-secondary"}`}
              style={{ padding: "0.2rem 0.6rem", fontSize: "0.75rem" }}
              onClick={() => onHoursChange(h)}
            >
              {h}h
            </button>
          ))}
        </div>
      </div>
      <div style={{ flex: 1, minHeight: 0, position: "relative" }}>
        <Line data={data} options={options} />
      </div>
    </div>
  );
};

import React, { useState } from "react";
import { Eye, ChevronLeft, ChevronRight, X, AlertCircle } from "lucide-react";
import { EventFilterParams } from "../api/client";
import { PaginatedEventsResponse, SecurityEvent } from "../types/api";

interface SecurityEventsTableProps {
  eventsData: PaginatedEventsResponse | null;
  isLoading: boolean;
  filters: EventFilterParams;
  onFilterChange: (filters: EventFilterParams) => void;
}

export const SecurityEventsTable: React.FC<SecurityEventsTableProps> = ({
  eventsData,
  isLoading,
  filters,
  onFilterChange,
}) => {
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const items = eventsData?.items ?? [];
  const total = eventsData?.total ?? 0;
  const limit = filters.limit ?? 25;
  const offset = filters.offset ?? 0;

  const handlePrevPage = () => {
    if (offset > 0) {
      onFilterChange({ ...filters, offset: Math.max(0, offset - limit) });
    }
  };

  const handleNextPage = () => {
    if (offset + limit < total) {
      onFilterChange({ ...filters, offset: offset + limit });
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
      case "high":
        return "badge-high";
      case "medium":
      case "warning":
        return "badge-warning";
      default:
        return "badge-info";
    }
  };

  return (
    <div className="glass-card" style={{ padding: "1.25rem", marginBottom: "2rem" }}>
      
      {/* Title & Filter Bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem", marginBottom: "1rem" }}>
        <div>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 600 }}>Security &amp; Resolver Event Log</h2>
          <p style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
            Persisted event trail from Member 1's EventBus into PostgreSQL
          </p>
        </div>

        {/* Filter controls */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
          
          {/* Domain Search */}
          <input
            type="text"
            placeholder="Filter domain..."
            value={filters.domain ?? ""}
            onChange={(e) => onFilterChange({ ...filters, domain: e.target.value || undefined, offset: 0 })}
            style={{ width: "160px", fontSize: "0.8rem" }}
          />

          {/* Client IP Search */}
          <input
            type="text"
            placeholder="Client IP..."
            value={filters.clientIp ?? ""}
            onChange={(e) => onFilterChange({ ...filters, clientIp: e.target.value || undefined, offset: 0 })}
            style={{ width: "130px", fontSize: "0.8rem" }}
          />

          {/* Event Type Filter */}
          <select
            value={filters.eventType ?? ""}
            onChange={(e) => onFilterChange({ ...filters, eventType: e.target.value || undefined, offset: 0 })}
            style={{ fontSize: "0.8rem" }}
          >
            <option value="">All Event Types</option>
            <option value="query_received">Query Received</option>
            <option value="blocked_request">Blocked Request</option>
            <option value="rate_limited">Rate Limited</option>
            <option value="suspicious_activity">Suspicious Activity</option>
            <option value="cache_hit">Cache Hit</option>
            <option value="cache_miss">Cache Miss</option>
            <option value="upstream_success">Upstream Success</option>
            <option value="upstream_failure">Upstream Failure</option>
          </select>

          {/* Severity Filter */}
          <select
            value={filters.severity ?? ""}
            onChange={(e) => onFilterChange({ ...filters, severity: e.target.value || undefined, offset: 0 })}
            style={{ fontSize: "0.8rem" }}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>

          {/* Synthetic Demo Toggle */}
          <label style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.8rem", color: "var(--text-secondary)", cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={filters.includeSynthetic ?? true}
              onChange={(e) => onFilterChange({ ...filters, includeSynthetic: e.target.checked, offset: 0 })}
            />
            Demo data
          </label>
        </div>
      </div>

      {/* Events Data Table */}
      <div style={{ overflowX: "auto", minHeight: "260px" }}>
        {isLoading && items.length === 0 ? (
          <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-secondary)" }}>
            Loading security events...
          </div>
        ) : items.length === 0 ? (
          <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
            <AlertCircle size={32} style={{ margin: "0 auto 0.5rem auto", opacity: 0.5 }} />
            <p>No events found matching the specified filters.</p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Severity</th>
                <th>Domain</th>
                <th>Client IP</th>
                <th>Action Taken</th>
                <th style={{ textAlign: "center" }}>Details</th>
              </tr>
            </thead>
            <tbody>
              {items.map((event) => {
                const date = new Date(event.timestamp);
                const timeStr = date.toLocaleTimeString([], { hour12: false }) + "." + String(date.getMilliseconds()).padStart(3, "0");
                return (
                  <tr key={event.id}>
                    <td className="font-mono" style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      {timeStr}
                    </td>
                    <td>
                      <span className="font-mono" style={{ fontSize: "0.8rem", color: "var(--text-primary)" }}>
                        {event.event_type}
                      </span>
                      {event.is_synthetic && (
                        <span style={{ marginLeft: "6px", fontSize: "0.65rem", color: "var(--accent-purple)", background: "rgba(139, 92, 246, 0.15)", padding: "1px 4px", borderRadius: "3px" }}>
                          synthetic
                        </span>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${getSeverityBadgeClass(event.severity)}`}>
                        {event.severity}
                      </span>
                    </td>
                    <td className="font-mono" style={{ color: event.severity === "high" || event.severity === "critical" ? "#fb7185" : "#38bdf8" }}>
                      {event.domain || "—"}
                    </td>
                    <td className="font-mono" style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                      {event.client_ip || "—"}
                    </td>
                    <td>
                      <span className="badge badge-info" style={{ fontSize: "0.7rem" }}>
                        {event.action_taken}
                      </span>
                    </td>
                    <td style={{ textAlign: "center" }}>
                      <button
                        onClick={() => setSelectedEvent(event)}
                        className="btn btn-secondary"
                        style={{ padding: "0.2rem 0.5rem", fontSize: "0.75rem" }}
                        title="View JSON metadata"
                      >
                        <Eye size={12} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination Footer */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "1rem", flexWrap: "wrap", gap: "0.5rem" }}>
        <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
          Showing {total > 0 ? offset + 1 : 0} to {Math.min(offset + limit, total)} of {total.toLocaleString()} events
        </span>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <button
            onClick={handlePrevPage}
            disabled={offset === 0 || isLoading}
            className="btn btn-secondary"
            style={{ padding: "0.3rem 0.6rem", fontSize: "0.75rem" }}
          >
            <ChevronLeft size={14} /> Previous
          </button>
          <button
            onClick={handleNextPage}
            disabled={offset + limit >= total || isLoading}
            className="btn btn-secondary"
            style={{ padding: "0.3rem 0.6rem", fontSize: "0.75rem" }}
          >
            Next <ChevronRight size={14} />
          </button>
        </div>
      </div>

      {/* Event Details Modal */}
      {selectedEvent && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: "rgba(0, 0, 0, 0.75)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 1000,
          padding: "1rem",
        }}>
          <div className="glass-card" style={{ width: "100%", maxWidth: "600px", background: "var(--bg-secondary)", padding: "1.5rem", border: "1px solid rgba(56, 189, 248, 0.4)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
              <div>
                <h3 style={{ fontSize: "1.1rem", fontWeight: 600 }}>Event #{selectedEvent.id} Details</h3>
                <span className="badge badge-info font-mono">{selectedEvent.event_type}</span>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="btn btn-secondary"
                style={{ padding: "0.3rem", borderRadius: "50%" }}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", fontSize: "0.85rem", marginBottom: "1rem" }}>
              <div><strong>Timestamp:</strong> <span className="font-mono">{selectedEvent.timestamp}</span></div>
              <div><strong>Severity:</strong> <span className={`badge ${getSeverityBadgeClass(selectedEvent.severity)}`}>{selectedEvent.severity}</span></div>
              <div><strong>Domain:</strong> <span className="font-mono">{selectedEvent.domain || "N/A"}</span></div>
              <div><strong>Client IP:</strong> <span className="font-mono">{selectedEvent.client_ip || "N/A"}</span></div>
              <div><strong>Record Type:</strong> <span className="font-mono">{selectedEvent.record_type || "N/A"}</span></div>
              <div><strong>Action Taken:</strong> <span>{selectedEvent.action_taken}</span></div>
            </div>

            <div>
              <strong style={{ fontSize: "0.85rem", display: "block", marginBottom: "0.4rem" }}>Metadata Payload:</strong>
              <pre style={{
                background: "rgba(0, 0, 0, 0.5)",
                padding: "0.75rem",
                borderRadius: "6px",
                fontSize: "0.75rem",
                overflowX: "auto",
                color: "#38bdf8",
                border: "1px solid var(--border-subtle)",
              }}>
                {JSON.stringify(selectedEvent.metadata_json, null, 2)}
              </pre>
            </div>

            <div style={{ marginTop: "1.25rem", textAlign: "right" }}>
              <button onClick={() => setSelectedEvent(null)} className="btn btn-secondary">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

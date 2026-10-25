import React from "react";
import { TopDomainItem } from "../types/api";

interface TopDomainsTableProps {
  topQueried: TopDomainItem[];
  topBlocked: TopDomainItem[];
}

export const TopDomainsTable: React.FC<TopDomainsTableProps> = ({ topQueried, topBlocked }) => {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
      
      {/* Top Queried Domains */}
      <div className="glass-card" style={{ padding: "1.25rem" }}>
        <h3 style={{ fontSize: "0.95rem", fontWeight: 600, marginBottom: "0.25rem" }}>Most Queried Domains</h3>
        <p style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginBottom: "0.75rem" }}>High-volume resolution targets</p>
        
        {topQueried.length === 0 ? (
          <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.85rem" }}>
            No domain query data available
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th style={{ textAlign: "right" }}>Queries</th>
              </tr>
            </thead>
            <tbody>
              {topQueried.map((item, idx) => (
                <tr key={idx}>
                  <td className="font-mono" style={{ color: "#38bdf8" }}>{item.domain}</td>
                  <td className="font-mono" style={{ textAlign: "right", fontWeight: 600 }}>{item.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Top Blocked Domains */}
      <div className="glass-card" style={{ padding: "1.25rem" }}>
        <h3 style={{ fontSize: "0.95rem", fontWeight: 600, marginBottom: "0.25rem" }}>Top Blocked Threat Targets</h3>
        <p style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginBottom: "0.75rem" }}>Blocked by security blocklist rules</p>
        
        {topBlocked.length === 0 ? (
          <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.85rem" }}>
            No blocked domain incidents
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th style={{ textAlign: "right" }}>Blocks</th>
              </tr>
            </thead>
            <tbody>
              {topBlocked.map((item, idx) => (
                <tr key={idx}>
                  <td className="font-mono" style={{ color: "#fb7185" }}>{item.domain}</td>
                  <td className="font-mono" style={{ textAlign: "right", fontWeight: 600, color: "#fb7185" }}>
                    {item.count.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

    </div>
  );
};

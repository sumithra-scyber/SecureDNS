import React, { useEffect, useState, useCallback } from "react";
import {
  EventFilterParams,
  fetchEventDistribution,
  fetchEvents,
  fetchHealth,
  fetchOverviewStats,
  fetchQueryVolume,
  fetchSecuritySummary,
  fetchTopDomains,
  triggerSeedData,
} from "./api/client";
import { EventDistributionItem, HealthResponse, OverviewStats, PaginatedEventsResponse, QueryVolumePoint, SecuritySummary, TopDomainItem } from "./types/api";
import { Header } from "./components/Header";
import { OverviewCards } from "./components/OverviewCards";
import { QueryVolumeChart } from "./components/QueryVolumeChart";
import { EventDistributionChart } from "./components/EventDistributionChart";
import { SecurityAlertsSummary } from "./components/SecurityAlertsSummary";
import { TopDomainsTable } from "./components/TopDomainsTable";
import { SecurityEventsTable } from "./components/SecurityEventsTable";
import { AlertTriangle } from "lucide-react";

export const App: React.FC = () => {
  // Telemetry state
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [overview, setOverview] = useState<OverviewStats | null>(null);
  const [volumeSeries, setVolumeSeries] = useState<QueryVolumePoint[]>([]);
  const [distribution, setDistribution] = useState<EventDistributionItem[]>([]);
  const [securitySummary, setSecuritySummary] = useState<SecuritySummary | null>(null);
  const [topQueried, setTopQueried] = useState<TopDomainItem[]>([]);
  const [topBlocked, setTopBlocked] = useState<TopDomainItem[]>([]);
  const [eventsData, setEventsData] = useState<PaginatedEventsResponse | null>(null);

  // Control state
  const [hours, setHours] = useState<number>(24);
  const [filters, setFilters] = useState<EventFilterParams>({ limit: 25, offset: 0, includeSynthetic: true });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSeeding, setIsSeeding] = useState<boolean>(false);
  const [autoRefreshInterval, setAutoRefreshInterval] = useState<number>(5000);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Fetch all dashboard data
  const loadDashboardData = useCallback(async () => {
    try {
      setErrorMessage(null);
      const [
        healthRes,
        overviewRes,
        volumeRes,
        distRes,
        secRes,
        queriedRes,
        blockedRes,
        eventsRes,
      ] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchOverviewStats(hours).catch(() => null),
        fetchQueryVolume(hours).catch(() => ({ time_window_hours: hours, series: [] })),
        fetchEventDistribution(hours).catch(() => []),
        fetchSecuritySummary(hours).catch(() => null),
        fetchTopDomains(8, hours, false).catch(() => []),
        fetchTopDomains(8, hours, true).catch(() => []),
        fetchEvents(filters).catch(() => null),
      ]);

      if (!healthRes) {
        setErrorMessage("Unable to connect to SecureDNS Monitoring API at http://127.0.0.1:8000. Ensure the FastAPI backend is running.");
      }

      setHealth(healthRes);
      setOverview(overviewRes);
      setVolumeSeries(volumeRes.series);
      setDistribution(distRes);
      setSecuritySummary(secRes);
      setTopQueried(queriedRes);
      setTopBlocked(blockedRes);
      setEventsData(eventsRes);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to load dashboard metrics");
    } finally {
      setIsLoading(false);
    }
  }, [hours, filters]);

  // Initial load
  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Auto-refresh interval
  useEffect(() => {
    if (autoRefreshInterval <= 0) return;
    const interval = setInterval(() => {
      loadDashboardData();
    }, autoRefreshInterval);
    return () => clearInterval(interval);
  }, [autoRefreshInterval, loadDashboardData]);

  // Trigger synthetic seed data
  const handleSeedDemo = async () => {
    setIsSeeding(true);
    try {
      await triggerSeedData(250);
      await loadDashboardData();
    } catch (err: any) {
      alert("Failed to seed demo data: " + err.message);
    } finally {
      setIsSeeding(false);
    }
  };

  return (
    <div style={{ maxWidth: "1440px", margin: "0 auto", padding: "1.5rem 1rem" }}>
      
      {/* Header with status and controls */}
      <Header
        health={health}
        isLoading={isLoading}
        onRefresh={loadDashboardData}
        autoRefreshInterval={autoRefreshInterval}
        onAutoRefreshChange={setAutoRefreshInterval}
        onSeedDemo={handleSeedDemo}
        isSeeding={isSeeding}
      />

      {/* Backend Disconnected Banner */}
      {errorMessage && (
        <div className="glass-card" style={{ padding: "0.85rem 1.25rem", marginBottom: "1.5rem", borderLeft: "4px solid var(--accent-amber)", background: "rgba(245, 158, 11, 0.1)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
            <AlertTriangle size={18} color="var(--accent-amber)" />
            <span style={{ fontSize: "0.85rem", color: "#fef3c7" }}>
              {errorMessage}
            </span>
          </div>
        </div>
      )}

      {/* Overview Metric Cards */}
      <OverviewCards stats={overview} isLoading={isLoading} />

      {/* Charts Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
        <QueryVolumeChart series={volumeSeries} hours={hours} onHoursChange={setHours} />
        <EventDistributionChart distribution={distribution} />
      </div>

      {/* Defensive Security Threat Cards */}
      <SecurityAlertsSummary summary={securitySummary} />

      {/* Top Queried & Top Blocked Domains */}
      <TopDomainsTable topQueried={topQueried} topBlocked={topBlocked} />

      {/* Filterable, Paginated Security Events Table */}
      <SecurityEventsTable
        eventsData={eventsData}
        isLoading={isLoading}
        filters={filters}
        onFilterChange={setFilters}
      />

      {/* Footer */}
      <footer style={{ textAlign: "center", color: "var(--text-muted)", fontSize: "0.75rem", padding: "1.5rem 0" }}>
        SecureDNS Intelligence Resolver • Team Project • Member 2 Monitoring &amp; Security Analytics Console
      </footer>

    </div>
  );
};
export default App;

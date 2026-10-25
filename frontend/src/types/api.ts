export interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
  database: "connected" | "disconnected";
  ingestion: {
    total_received?: number;
    total_persisted?: number;
    total_dropped?: number;
    queue_current_size?: number;
    queue_max_size?: number;
    [key: string]: any;
  };
}

export interface SecurityEvent {
  id: number;
  timestamp: string;
  event_type: string;
  severity: "info" | "warning" | "medium" | "high" | "critical";
  action_taken: string;
  domain: string | null;
  client_ip: string | null;
  record_type: string | null;
  metadata_json: Record<string, any>;
  is_synthetic: boolean;
}

export interface PaginatedEventsResponse {
  items: SecurityEvent[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface OverviewStats {
  time_window_hours: number;
  total_events: number;
  total_queries: number;
  queries_per_second: number;
  blocked_queries: number;
  rate_limited_queries: number;
  suspicious_queries: number;
  security_incidents_total: number;
  cache_hits: number;
  cache_misses: number;
  cache_hit_rate_pct: number;
  upstream_failures: number;
}

export interface QueryVolumePoint {
  timestamp: string;
  queries: number;
  blocked: number;
  security_alerts: number;
  cache_hits: number;
}

export interface QueryVolumeResponse {
  time_window_hours: number;
  series: QueryVolumePoint[];
}

export interface EventDistributionItem {
  event_type: string;
  severity: string;
  count: number;
}

export interface TopDomainItem {
  domain: string;
  count: number;
}

export interface SecuritySummary {
  time_window_hours: number;
  blocked_queries: number;
  rate_limited_queries: number;
  suspicious_queries: number;
  total_security_events: number;
  top_blocked_domains: TopDomainItem[];
}

import {
  EventDistributionItem,
  HealthResponse,
  OverviewStats,
  PaginatedEventsResponse,
  QueryVolumeResponse,
  SecurityEvent,
  SecuritySummary,
  TopDomainItem,
} from "../types/api";

const BASE_URL = import.meta.env.VITE_API_URL || "/api";

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`API error ${res.status}: ${errorText || res.statusText}`);
  }
  return res.json();
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${BASE_URL}/health`);
  return handleResponse<HealthResponse>(res);
}

export async function fetchOverviewStats(hours: number = 24): Promise<OverviewStats> {
  const res = await fetch(`${BASE_URL}/stats/overview?hours=${hours}`);
  return handleResponse<OverviewStats>(res);
}

export async function fetchQueryVolume(hours: number = 24): Promise<QueryVolumeResponse> {
  const res = await fetch(`${BASE_URL}/stats/query-volume?hours=${hours}`);
  return handleResponse<QueryVolumeResponse>(res);
}

export async function fetchEventDistribution(hours: number = 24): Promise<EventDistributionItem[]> {
  const res = await fetch(`${BASE_URL}/stats/event-distribution?hours=${hours}`);
  const data = await handleResponse<{ distribution: EventDistributionItem[] }>(res);
  return data.distribution;
}

export async function fetchTopDomains(
  limit: number = 8,
  hours: number = 24,
  blockedOnly: boolean = false
): Promise<TopDomainItem[]> {
  const res = await fetch(
    `${BASE_URL}/stats/top-domains?limit=${limit}&hours=${hours}&blocked_only=${blockedOnly}`
  );
  const data = await handleResponse<{ domains: TopDomainItem[] }>(res);
  return data.domains;
}

export async function fetchSecuritySummary(hours: number = 24): Promise<SecuritySummary> {
  const res = await fetch(`${BASE_URL}/stats/security-summary?hours=${hours}`);
  return handleResponse<SecuritySummary>(res);
}

export interface EventFilterParams {
  eventType?: string;
  severity?: string;
  domain?: string;
  clientIp?: string;
  limit?: number;
  offset?: number;
  includeSynthetic?: boolean;
}

export async function fetchEvents(params: EventFilterParams = {}): Promise<PaginatedEventsResponse> {
  const q = new URLSearchParams();
  if (params.eventType) q.set("event_type", params.eventType);
  if (params.severity) q.set("severity", params.severity);
  if (params.domain) q.set("domain", params.domain);
  if (params.clientIp) q.set("client_ip", params.clientIp);
  if (params.limit !== undefined) q.set("limit", params.limit.toString());
  if (params.offset !== undefined) q.set("offset", params.offset.toString());
  if (params.includeSynthetic !== undefined) q.set("include_synthetic", params.includeSynthetic.toString());

  const res = await fetch(`${BASE_URL}/events?${q.toString()}`);
  return handleResponse<PaginatedEventsResponse>(res);
}

export async function fetchEventById(id: number): Promise<SecurityEvent> {
  const res = await fetch(`${BASE_URL}/events/${id}`);
  return handleResponse<SecurityEvent>(res);
}

export async function triggerSeedData(count: number = 250): Promise<{ status: string; seeded_events: number }> {
  const res = await fetch(`${BASE_URL}/dev/seed?count=${count}`, {
    method: "POST",
  });
  return handleResponse(res);
}

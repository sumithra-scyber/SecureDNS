# SecureDNS — Viva & Presentation Defense Guide

This guide prepares you to explain and defend Member 2's monitoring system, database design, asynchronous event pipeline, and integration with Member 1's DNS resolver.

---

## 1. Core Architectural Questions & Model Answers

### Q1: Why did you decouple event emission from database writes using an asyncio queue?
**Answer:**
> "In high-performance networking, a DNS resolver must answer UDP packets in single-digit milliseconds. Database operations (like writing to PostgreSQL) are I/O bound and can experience network latency spikes, connection timeouts, or database locks.
> 
> If Member 1's resolver had written directly to the database during query resolution, every DNS query would be stalled waiting for SQL disk writes, degrading throughput from tens of thousands of queries per second down to just a few hundred.
> 
> By introducing a non-blocking `asyncio.Queue` between the resolver's synchronous `EventBus` and our persistence layer, `event_bus.publish()` finishes in less than **3 microseconds**. A dedicated background worker consumes events in batches of 100, minimizing database transactions and insulating the resolver from database downtime."

### Q2: How does the system handle backpressure if PostgreSQL becomes slow or crashes?
**Answer:**
> "We implemented a bounded buffer with a maximum capacity of 10,000 items. If database writes fall behind and the queue fills up, our handler drops the oldest queued event, increments a drop counter, and logs a warning.
> 
> This guarantees that under severe database failure or DDoS flood, memory usage remains strictly bounded, the operating system never runs out of RAM, and DNS resolution for clean clients continues without interruption."

### Q3: Why is the EventBus handler defined as a synchronous function rather than an async function?
**Answer:**
> "Inspecting Member 1's implementation revealed that `EventBus.publish()` iterates through handlers synchronously (`for h in self._handlers: h(event)`).
> 
> If we registered an `async def` handler, calling `h(event)` would only return an un-awaited Python coroutine object, triggering a `RuntimeWarning: coroutine was never awaited` and losing the event entirely.
> 
> Therefore, our handler is a synchronous method that uses `queue.put_nowait()` to safely enqueue the event onto the running asyncio event loop without blocking or requiring an await expression."

### Q4: How does your database schema support high-velocity time-series analytics?
**Answer:**
> "DNS monitoring generates high volumes of timestamped records. We designed `security_events` with single-column indexes on `timestamp`, `event_type`, `severity`, and `domain`, as well as composite indexes:
> 1. `(timestamp, event_type)` for filtering timeline volume queries.
> 2. `(timestamp, severity)` for quick aggregation of threat levels over a 24-hour window.
> 3. `(domain, event_type)` for calculating top queried and top blocked domains without scanning the entire table.
> 
> Furthermore, unstructured metadata (like latency, tunneling warnings, and transport type) is stored in a `JSON` column, allowing flexible event-specific payloads without altering the table schema."

### Q5: How do you differentiate between authentic runtime events and synthetic demo data?
**Answer:**
> "Every event record contains a boolean column `is_synthetic`. Genuine resolver events default to `false`. When using the demonstration seed generator for testing or viva presentations, records are explicitly tagged with `is_synthetic = true`.
> 
> The API and frontend provide a filter toggle so that synthetic events can be viewed during a demo or excluded completely to view pristine production traffic."

---

## 2. End-to-End Live Demonstration Script (Step-by-Step)

Follow this exact script when demonstrating the project to professors or examiners:

### Step 1: Start the Integrated System
```bash
# Terminal 1: Starts Resolver on port 5300 + Monitoring API on port 8000
python -m securedns.run_all
```
*Point out to examiners:* Both the UDP/TCP DNS listener and the FastAPI server boot seamlessly together, with the monitoring event handler subscribed to Member 1's EventBus.

### Step 2: Launch the Frontend Console
```bash
# Terminal 2: Starts the Vite React dashboard
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser.
*Show examiners:*
- Glassmorphism dark-mode UI with live telemetry badges.
- Database connection status indicator.
- Real-time buffer status showing active queue size and total events persisted.

### Step 3: Trigger Live DNS Traffic (Normal Query)
In a third terminal, send a DNS query for an allowed domain:
```bash
# Windows PowerShell
Resolve-DnsName -Name google.com -Server 127.0.0.1 -Port 5300
```
*Observe on Dashboard:*
- Total Queries card increments.
- Query volume chart registers the query.
- Event log table displays a `query_received` event followed by a `cache_hit` or `upstream_success` event with measured latency.

### Step 4: Demonstrate Threat Interception (Blocked Domain)
Send a query for a malicious domain listed in the blocklist:
```bash
Resolve-DnsName -Name malware-traffic-analysis.net -Server 127.0.0.1 -Port 5300
```
*Observe on Dashboard:*
- Resolver returns `REFUSED`.
- The Blocked Queries card increments.
- The Threat Intelligence summary flags the block.
- Top Blocked Domains table updates in real time.

### Step 5: Demonstrate Token Bucket Rate Limiting
Execute a rapid burst of queries to exceed the configured rate limit (20 QPS):
```bash
1..30 | ForEach-Object { Resolve-DnsName -Name example.com -Server 127.0.0.1 -Port 5300 }
```
*Observe on Dashboard:*
- The Rate Limited queries counter increments.
- Event log shows `rate_limited` events with severity `medium` and action `RATE_LIMITED`.

### Step 6: Demonstrate Synthetic Demo Data Seeding
Click the **Seed Demo Data** button in the dashboard header.
*Observe on Dashboard:*
- 250+ realistic multi-hour events populate the query volume timeline and event distribution doughnut chart.
- Examiners can see how the platform looks under 24 hours of enterprise-scale DNS traffic.

---

## 3. Key Concepts Checklist

| Concept | Explanation |
|---|---|
| **DNS Wire Format** | 12-byte header with Transaction ID, flags (QR, Opcode, AA, TC, RD, RA, RCODE), and question/answer counts. |
| **Transaction ID Matching** | Resolver must match the 2-byte transaction ID of client queries, rewriting cached responses so clients accept them. |
| **Token Bucket vs Leaky Bucket** | Token bucket allows short bursts up to burst capacity (`burst=40`) while enforcing long-term average rate (`rate=20`). |
| **TTL Clamping** | Clamping upstream TTLs between `min_ttl` (30s) and `max_ttl` (3600s) prevents cache poisoning and stale records. |
| **FastAPI Dependency Injection** | `Depends(get_db_session)` provides automatic session rollback on error and clean connection lifecycle management. |
| **Pydantic v2 Serialization** | Enforces strict type validation and automatic OpenAPI 3.0 schema generation at `/docs`. |

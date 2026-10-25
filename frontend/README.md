# SecureDNS Monitoring Frontend

Modern, high-performance security intelligence dashboard built with React 18, TypeScript, Vite, and Chart.js.

## Features

- **Real-Time Telemetry Cards**: Monitor total DNS queries, live queries per second (QPS), cache hit rates, and blocked threats.
- **Query Volume & Security Timeline**: Interactive Chart.js timeline with selectable resolution windows (6h, 12h, 24h, 48h).
- **Event Class Distribution**: Doughnut visualization categorizing DNS resolution traffic and defensive blocks.
- **Threat Intelligence Summary**: Breakdown of threats intercepted by the Domain Blocklist, Token Bucket Rate Limiter, and Query Inspector.
- **Top Queried & Blocked Domains**: Instant visibility into high-volume targets and recurring attack sources.
- **Filterable Event Log**: Searchable and paginated table with metadata drill-down modal for every event.
- **Demo Mode Support**: Dedicated "Seed Demo Data" action for instant project demonstrations and presentations.

## Development Setup

```bash
# 1. Install dependencies
npm install

# 2. Run local dev server (proxies /api to http://127.0.0.1:8000)
npm run dev

# 3. Production build
npm run build
```

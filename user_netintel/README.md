# User Network Intelligence (Streamlit)

Type a `user.name`, get the full story of that user's network behaviour: a risk verdict, a plain-English summary, explainable findings mapped to MITRE ATT&CK, and drill-down tabs.

```bash
pip install -r requirements.txt
streamlit run app.py
```

## How it's built

```
query_dict.py     every Elasticsearch request body (18 functions, ECS fields only)
data_source.py    search(body) -> ES-shaped response. Mock by default; real cluster via env vars
es_mock_engine.py executes the query dicts against mock events (terms, multi_terms, date_histogram,
                  filter, cardinality, percentiles, geo_centroid, top_hits, ...), so editing a query changes the result
mock_data.py      ~60k synthetic ECS events (flows, DNS, VPN) for 16 users with planted incidents
parsers.py        ES response -> pandas DataFrames (shape-only; doesn't care if data is mock or real)
analysis.py       investigate(user, start, end, tz): runs the queries, parses, runs 10 detectors, scores, narrates
charts.py         every Plotly figure, one consistent dark palette
app.py            the page
```

Data flow: `query_dict` → `data_source.search` → `parsers` → `analysis` (detections + score) → `app` (charts).

### Switch to a real cluster
```bash
export NETINTEL_ES_URL=https://my-cluster:9200
export NETINTEL_ES_API_KEY=...            # or NETINTEL_ES_USER / NETINTEL_ES_PASSWORD
export NETINTEL_ES_INDEX="logs-network_traffic.*,logs-vpn.*"
pip install elasticsearch
```
Nothing else changes. Expected datasets: `event.dataset` = `network_traffic.flow`, `network_traffic.dns`, `vpn.session` (rename in `query_dict.py`).

## What the page shows

| Section | Insight | Key ECS fields |
|---|---|---|
| Watchlist (landing) | every user ranked by risk: "who do I look at first?" | all |
| Identity card | hosts, internal IP/MAC, VPN origins, first/last seen | `user.*`, `host.*`, `source.ip`, `source.mac` |
| Risk + narrative | 0-100 score, verdict, 4-5 sentence summary | - |
| KPIs | connections, up/down bytes, distinct destinations, failed %, open sessions, with deltas vs previous window and daily sparklines | `source.bytes`, `destination.bytes`, `event.outcome`, `event.end` |
| Findings | each with evidence table, next steps, MITRE link, the query that produced it | - |
| Timeline | upload/download over time with off-hours shading and finding markers; weekday × hour heatmaps | `@timestamp` |
| Destinations | Sankey host → protocol → AS org (weight by up/down/connections); ranked table with new-domain flags | `destination.*`, `network.protocol` |
| Geo & sessions | world arcs to destination countries; VPN logins with implied travel speed; sessions open right now | `destination.geo.*`, `source.geo.*`, `event.end` |
| DNS | entropy vs label-length scatter (tunnelling / DGA), top domains, NXDOMAIN timeline | `dns.question.*`, `dns.response_code` |
| Detections | beacon regularity chart, 5-minute fan-out, scan target × port grid, admin-protocol sessions | `destination.port`, `event.outcome` |
| Peers | user as × department median per metric | `user.group.name` |
| Query inspector | every query body + trimmed response + an editable playground | - |

## Detectors (analysis.py → `detect`)
1. **Large upload**: ≥1 GB, or ≥200 MB with up:down ≥ 20:1. Critical if the domain is new or it happened off-hours (T1048)
2. **Impossible travel**: consecutive VPN logins implying > 900 km/h (T1078)
3. **Beaconing**: per-minute histogram per dest:port; gap coefficient of variation < 0.35 over ≥ 6 h (T1071.001)
4. **DNS tunnelling**: ≥ 50 unique names under one domain with ~30+ char labels (T1071.004)
5. **DGA**: ≥ 25 random-looking NXDOMAIN registered domains (T1568.002)
6. **Internal scan**: ≥ 40 hosts (or 8 ports × 15 hosts) in 5 min (T1046)
7. **Lateral movement**: successful SMB/RDP/WinRM/SSH to ≥ 4 internal hosts; critical if after a scan (T1021)
8. **Peer outlier**: internet uploads > 5× department median
9. **Off-hours**: off-hours connection share or upload share well above peers
10. **New destinations / many failures**: context

Score = `1 − Π(1 − w)` with critical .45 / high .30 / medium .15 / low .05; any critical floors it at 80, any high at 55.

## Demo users
`jdoe` (exfil + impossible travel) · `asmith` (beacon + DGA + DNS tunnel) · `bwayne` (scan → lateral movement) · `mlopez` (clean). Malicious infrastructure uses documentation IP ranges and invented domains.

Note: the world map downloads its basemap from cdn.plot.ly, so the browser needs internet access.

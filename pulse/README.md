# 💓 Pulse — a fleet lab

Six patterns that never show up event by event, only across everyone over time.
Built from nothing but process-creation telemetry (Sysmon 1 / Security 4688 in ECS).

```bash
pip install -r requirements.txt
streamlit run app.py                       # 21-day mock fleet (26 people, 6 teams)
FTD_MODE=elastic ES_URL=https://host:9200 ES_API_KEY=... streamlit run app.py
```

## The exhibits

| # | Exhibit | Question | How |
|---|---|---|---|
| 01 | **Heartbeat Detector** 💓 | Human or machine? | Every (host, exe, command shape) stream: median gap, regularity (share of gaps within ±25%), absolute jitter, off-hours share. Regular + unsigned / user-writable / under a person's account / at night = unexplained. Also finds people's daily clockwork. |
| 02 | **Outbreak Curves** 🦠 | How did each new binary spread, and through what? | First launch per (hash, host) after a burn-in → patient zero, spread curve, t50, acceleration, and the launch channel (update service / email app / user / remote service). Classified as managed, organic, phishing-like or worm-like. |
| 03 | **Grammar of Work** 📖 | Which sentences don't fit? | Per-person bigram model of app launches, backed off to team → company → app frequency, scored leave-the-day-out. Sentences ranked by excess surprise; each comes with "usually X (42%), here Y — odds 1 in N". Plus each team's real workflows (Sankey). |
| 04 | **Shadow Org Chart** 🗺️ | Who actually works like whom? | TF-IDF app mix + hour-of-day profile → SVD map. Leave-one-out team centroids find people who work like another team; per-session comparison finds sessions that look like a *different* person (shared credentials / takeover). |
| 05 | **Novelty Frontier** 🌅 | Is the fleet still learning? | First-seen curve of hashes, parent→child pairs and command shapes. After a burn-in, spikes are labelled explained (signed + pushed by update services) or not — with where the novelty concentrated. |
| 06 | **Process Physics** ⚛️ | Which life cycles break the rules? | `process.start/end` joined to the parent by `entity_id`: orphans, **spawn-and-vanish** (parent dies in < 3 s, child lives on), and immortals (3+ days). |
| ∞ | **Live pulse** | | Polls new launches; anything matching an unexplained rhythm from 01 lights up. |

## Privacy mode
People are pseudonymized by default (`F·a3f2`). Revealing names requires a reason and is logged in the sidebar.
Exhibits 03 and 04 model individual behaviour — check your client's rules (GDPR, works councils) before turning names on.

## Files
| file | job |
|---|---|
| `exhibits.py` | all six analyses (pandas/numpy, no UI) |
| `app.py` | the Streamlit lab |
| `query_dict.py` | what the app queries, plus **at-scale** composite aggregations for large fleets |
| `mock_responses.py` | the 21-day mock fleet with one planted story per exhibit |
| `data_source.py` | mock ↔ real switch + `search_after` paging |

## At scale
The app pulls raw events (fine up to a few hundred thousand). On a big fleet, use the `*_at_scale`
builders in `query_dict.py` (composite aggs for rhythm candidates, first-seen per hash/pair, per-user app mix),
or an Elastic **transform** that maintains them continuously, and only pull raw timestamps for the streams that matter.

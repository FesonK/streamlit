# 🔎 Deep String Finder

A Streamlit search page for hunting strings buried deep inside ECS documents.
It runs entirely on mock data, but the queries it builds are real Elasticsearch DSL.

```bash
pip install -r requirements.txt
streamlit run app.py
```

| File | What it does |
|---|---|
| `query_dict.py` | Pure functions that build the `_search` request: indices, `@timestamp` range, `query_string` (Lucene), highlight, aggs |
| `mock_data.py` | ~890 fake ECS docs with planted needles, plus `mock_search(index, body)`, which returns an ES-shaped response |
| `app.py` | The UI: search bar, index / time / field-scope filters, hit charts, highlighted result cards, mock Kibana links, DSL panel, CSV export |
| `.streamlit/config.toml` | Dark theme |

## Going live

In `app.py`, replace

```python
resp = mock_search(req["index"], req["body"])
```

with

```python
from elasticsearch import Elasticsearch
es = Elasticsearch("https://your-cluster:9200", api_key="...")
resp = es.search(index=req["index"], body=req["body"])
```

Then point `KIBANA_BASE` and `DATA_VIEW_ID` in `query_dict.py` at your Kibana instance.

## Planted needles to try

`*sekurlsa*` · `x7k2-update.com` · `process.command_line:*-enc*` · `*Invoke-Mimikatz*` ·
`url.full:*password=*` · `dns.question.name:*exfil*` · `"authorized_keys"` · `*minexmr* OR *kworkerd*` ·
`*pastebin*` (Last 30 days) · `198.51.100.23 AND NOT event.code:4624` · `*svc_update*`

One of the `x7k2-update.com` hits is hidden inside a base64 `-enc` PowerShell blob, so a plain
search can't find it. That's the case for a v2 base64-decode feature.

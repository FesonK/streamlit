# 🌳 Family Tree Detective

Pick a `user.name`, see every process they launched as a family tree, and let suspicious branches float to the top.

    pip install -r requirements.txt
    streamlit run app.py                     # mock data (default)

    # real cluster later — nothing else changes:
    FTD_MODE=elastic ES_URL=https://...:9200 ES_API_KEY=... streamlit run app.py

| file | job |
|---|---|
| `query_dict.py` | every Elastic request (users list, summary aggs, paged process pull, live polling) |
| `mock_responses.py` | fake Elastic: 14 days of ECS/Sysmon data for 5 users, responses shaped like the real thing |
| `data_source.py` | the mock ↔ real switch (`FTD_MODE`) + `search_after` paging |
| `detections.py` | readable risk rules (Office→shell, encoded PowerShell, LOLBin downloads, masquerading, …) |
| `app.py` | the Streamlit page |

Planted stories in the mock: **bob.martin** (phishing macro → encoded PowerShell → certutil → rundll32 → recon),
**erin.patel** (fake `svchost.exe` in %TEMP%), **alice.wong** (unsigned installer), **dave.kim** (~10k harmless build
processes, scale test), **carol.diaz** (clean).

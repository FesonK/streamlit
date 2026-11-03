# 🧅 Peel

Reassemble, **deobfuscate**, and tag the PowerShell that actually ran on your
fleet — built on Elastic's `powershell.*` fieldset (script-block 4104, module
4103, engine 400/403) plus process-creation (4688 / Sysmon 1) for cmd.exe.

```bash
pip install -r requirements.txt
python train_score.py          # fit the obfuscation score (writes score_model.json)
streamlit run app.py           # mock data (default)

# point at a real cluster — only this changes:
FTD_MODE=elastic ES_URL=https://host:9200 ES_API_KEY=... streamlit run app.py
```

## What it does

PowerShell logs the text of each layer it runs, but it logs that text **exactly
as written** — obfuscation and all. So Peel does two separate jobs:

1. **Link the layers.** When a block runs a decoded payload (`IEX`,
   `ScriptBlock::Create`), PowerShell writes that payload as its *own* new 4104.
   Peel chains parent→child by host + runspace + a tight time window, and by
   content (the child's text is what the parent handed to `IEX`). One attack
   reads as layer 1 → 2 → 3 instead of three unrelated events.
2. **Deobfuscate within a block, from the syntax tree — never regex, never
   execution.** `psparse.py` tokenizes and parses the obfuscation-relevant
   subset of PowerShell, constant-folds every sub-expression it can
   (`'Down'+'load'`, `"{1}{0}"-f…`, `[char[]](…)-join''`, `-bxor`, string
   reversal, `.Replace`, `[Convert]::FromBase64String`,
   `[Text.Encoding]::Unicode.GetString`, dynamic member/command names, backticks,
   random case, single-assignment variables), and rewrites only those spans.
   Nothing is ever run.

It also **scores** obfuscation instead of just removing it: a tiny
logistic-regression model (Revoke-Obfuscation style) over syntax-tree features —
backtick density, how much peeling changed the code, random-case ratio, dynamic
invocation, char-code/format/join operators, tiny string fragments, entropy.
5-fold cross-val **AUC ≈ 0.93**, and `peel(obfuscate(x)) == x` on 100% of the
round-trip tests.

## Tabs

| Tab | What it shows |
|---|---|
| 🎬 **Sessions** | Each runspace as a replayable transcript, riskiest first; inspect any entry. |
| 🧅 **Peel a block** | Any block, most-obfuscated first; before/after diff + linked layers. |
| 📡 **Rare & risky** | Every command normalized to a **fingerprint** and counted fleet-wide; rare + tagged rises. |
| 🧪 **Try it** | Paste your own PowerShell (or a `-enc` command line) and watch it peel. |
| 🩺 **Data doctor** | Field-coverage report — tells you what to map in `normalize.py` before trusting real data. |
| 📶 **Live** | Polls for new blocks, peels + tags each as it arrives. |

**Blind Spots** strip (top): PowerShell **v2 downgrades** (no script-block
logging, no AMSI), **logging gaps** (a `-enc` launch with no matching 4104), and
**remote sessions** (`connected_user` ≠ `user`).

Technique tags carry their **MITRE ATT&CK** id (download cradle, AMSI/Defender
tampering, credential access, persistence, lateral movement, …) and are applied
to the *peeled* text, so obfuscated tradecraft is caught after the disguise comes
off.

## Files

| file | job |
|---|---|
| `psparse.py` | PowerShell tokenizer + parser + constant-folding deobfuscator + obfuscation features |
| `obfuscator.py` | Invoke-Obfuscation-style transforms (for mock data + training + round-trip tests) |
| `corpus.py` | clean admin/dev PowerShell (training + benign mock traffic) |
| `train_score.py` | fits `score_model.json` |
| `detections.py` | ATT&CK technique rules + command fingerprint + risk score |
| `query_dict.py` | every Elastic request |
| `mock_responses.py` | fake Elastic: ECS-shaped 4104/4103/400/1 events with planted stories |
| `normalize.py` | field mapping (`FIELD_PATHS`) + the Data Doctor |
| `data_source.py` | mock ↔ real switch (`FTD_MODE`) + `search_after` paging |
| `sessions.py` | stitch split blocks, link layers, assemble + enrich sessions |
| `app.py` | the Streamlit page |

## Moving to real data

This is the "morph my data into the mock shape" step, and it's config, not code:

1. Run the app, open **🩺 Data doctor**. It samples recent events and reports how
   well each field Peel needs is populated.
2. For anything **missing**, add your source's path to `FIELD_PATHS` in
   `normalize.py` (it already covers the common `winlog.event_data.*` spellings).
3. Re-check. When the criticals are green, flip `FTD_MODE=elastic`.

Script-block logging (4104) is the main source and is **off by default** in
Windows — turn on *Module Logging* and *Script Block Logging* via GPO. Where it's
off, the Blind Spots and the process/`-enc` path still carry a lot.

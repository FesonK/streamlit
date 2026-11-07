"""
exhibits.py — the six analyses behind Pulse. Pure pandas/numpy, no UI.

  heartbeat()   💓 human vs machine rhythm of every (host, exe, command) stream
  outbreaks()   🦠 how each new binary spread through the fleet, and by what channel
  grammar()     📖 per-person sequence model of app launches; sentences that don't fit
  org_chart()   🗺️ behavioral fingerprints → map of who works like whom; takeovers
  novelty()     🌅 first-seen curve of hashes, parent→child pairs and command shapes
  physics()     ⚛️ process lifecycle oddities: orphans, spawn-and-vanish, immortals

Every finding carries a plain-English "why", so nothing is a black box.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

SYSTEM_ACCOUNTS = {"system", "local service", "network service"}
SCHED_PARENTS = {"svchost.exe", "taskhostw.exe", "taskeng.exe", "services.exe", "msmpeng.exe"}
SYSTEM_PARENTS = SCHED_PARENTS | {"userinit.exe", "winlogon.exe", "smss.exe", "csrss.exe", "wininit.exe",
                                  "wmiprvse.exe", "dllhost.exe", "runtimebroker.exe", "sihost.exe", "ccmexec.exe"}
DEPLOY_PARENTS = {"ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe", "svchost.exe",
                  "msmpeng.exe", "microsoftedgeupdate.exe", "googleupdate.exe", "trustedinstaller.exe",
                  "tiworker.exe", "msiexec.exe"}
EMAIL_PARENTS = {"outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "olk.exe"}
USER_PARENTS = {"explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe"}
REMOTE_PARENTS = {"services.exe", "wmiprvse.exe", "psexesvc.exe", "winrshost.exe", "wsmprovhost.exe"}
USER_WRITABLE = (r"\appdata\local\temp", r"\users\public", r"\downloads", r"\windows\temp", r"\content.outlook",
                 r"\appdata\roaming\microsoft\windows\start menu")
DEPT_NAMES = {"FIN": "Finance", "SAL": "Sales", "HR": "People", "DEV": "Engineering", "IT": "IT", "MKT": "Marketing",
              "OTHER": "Other"}


# ───────────────────────── frame ─────────────────────────
def _get(d: dict, path: str):
    for p in path.split("."):
        if not isinstance(d, dict) or p not in d:
            return None
        d = d[p]
    return d


def frame(hits: list[dict]) -> pd.DataFrame:
    rows = []
    for h in hits:
        s = h.get("_source", h)
        p = s.get("process", {}) or {}
        pa = p.get("parent", {}) or {}
        cs = p.get("code_signature", {}) or {}
        rows.append((s.get("@timestamp"), _get(s, "host.name"), _get(s, "user.name"),
                     (p.get("name") or "").lower(), p.get("executable") or "", p.get("command_line") or "",
                     p.get("entity_id"), pa.get("entity_id"), (pa.get("name") or "").lower(),
                     p.get("start") or s.get("@timestamp"), p.get("end"), (p.get("hash") or {}).get("sha256"),
                     cs.get("trusted"), cs.get("subject_name")))
    df = pd.DataFrame(rows, columns=["ts", "host", "user", "name", "exe", "cmd", "eid", "peid", "pname",
                                     "start", "end", "sha256", "trusted", "signer"])
    for c in ("ts", "start", "end"):
        df[c] = pd.to_datetime(df[c], utc=True, format="ISO8601", errors="coerce").dt.as_unit("ns")
    df["user"] = df["user"].fillna("?")
    df["host"] = df["host"].fillna("?")
    df["human"] = ~df["user"].str.lower().isin(SYSTEM_ACCOUNTS)
    df["signed"] = df["trusted"].eq(True)
    df["dept"] = df["host"].str.extract(r"^WS-([A-Z]+)-", expand=False).fillna("OTHER")
    df["cshape"] = cmd_shape(df["cmd"])
    low = (df["exe"] + " " + df["cmd"]).str.lower()
    df["writable"] = False
    for w in USER_WRITABLE:
        df["writable"] |= low.str.contains(w, regex=False)
    return df.sort_values("ts").reset_index(drop=True)


def cmd_shape(cmd: pd.Series) -> pd.Series:
    """Normalize a command line to its shape so variants of the same command collapse."""
    s = cmd.fillna("").str.lower()
    s = s.str.replace(r"c:\\users\\[^\\\s\"]+\\", r"c:\\users\\<u>\\", regex=True)
    s = s.str.replace(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", "<guid>", regex=True)
    s = s.str.replace(r"[^\\\"\s]+\.(?:docx?|xlsx?|pptx?|pdf|txt|csv|msg)\b", "<file>", regex=True)
    s = s.str.replace(r"\d+", "<n>", regex=True)
    return s.str.replace(r"\s+", " ", regex=True).str.strip()


def human_period(sec: float) -> str:
    if sec < 90:
        return f"{sec:.0f} s"
    if sec < 5400:
        return f"{sec / 60:.0f} min"
    if sec < 2 * 86400:
        return f"{sec / 3600:.1f} h"
    return f"{sec / 86400:.1f} d"


# ───────────────────────── 💓 heartbeat ─────────────────────────
def heartbeat(df: pd.DataFrame, min_n: int = 10) -> pd.DataFrame:
    """Split every (host, executable, command shape) stream into human / machine / routine
    by the rhythm of its launches. Machines are periodic; people are bursty."""
    key = df["host"] + "|" + df["exe"].str.lower() + "|" + df["cshape"]
    d = df.assign(key=key)
    sizes = d.groupby("key").size()
    d = d[d["key"].isin(sizes[sizes >= min_n].index)]
    out = []
    for k, g in d.groupby("key", sort=False):
        t = g["ts"].astype("int64").to_numpy() / 1e9
        gaps = np.diff(np.sort(t))
        gaps = gaps[gaps > 0.5]
        if len(gaps) < min_n - 1:
            continue
        med = float(np.median(gaps))
        mad = float(np.median(np.abs(gaps - med)))
        jitter = mad / med if med else 1.0
        regular = float(np.mean(np.abs(gaps - med) <= 0.25 * med))
        mu, sd = gaps.mean(), gaps.std()
        burst = float((sd - mu) / (sd + mu)) if (sd + mu) else 0.0
        hrs = g["ts"].dt.hour
        offhours = float(((hrs < 7) | (hrs >= 20) | (g["ts"].dt.weekday >= 5)).mean())
        if regular >= 0.6 and jitter <= 0.25:
            # long periods: machines hit the same second, people drift by minutes
            cls = "human routine" if (med >= 6 * 3600 and mad > 300) else "machine"
        elif regular < 0.35:
            cls = "human"
        else:
            cls = "mixed"
        first = g.iloc[0]
        human_acct = bool(first["human"])
        reasons, score = [], 0
        if cls == "machine":
            if not first["signed"]:
                reasons.append("unsigned binary"); score += 3
            if bool(g["writable"].any()):
                reasons.append("runs from or loads a user-writable path"); score += 3
            if human_acct:
                reasons.append(f"scheduled under a person's account ({first['user']}), not SYSTEM"); score += 1
                if offhours >= 0.2:
                    reasons.append(f"fires at night/weekends ({offhours:.0%} of runs) when {first['user']} isn't working")
                    score += 2
        tod = g["ts"].dt.hour * 60 + g["ts"].dt.minute
        out.append({
            "key": k, "host": first["host"], "user": first["user"], "name": first["name"], "exe": first["exe"],
            "cmd": first["cmd"], "pname": first["pname"], "signed": bool(first["signed"]), "n": len(g),
            "period_s": med, "period": human_period(med), "jitter": jitter, "regularity": regular,
            "burstiness": burst, "offhours": offhours, "mad_s": mad, "cls": cls, "reasons": reasons, "suspicion": score,
            "level": "high" if score >= 4 else ("low" if score >= 1 else "explained") if cls == "machine" else "",
            "first": g["ts"].min(), "last": g["ts"].max(),
            "tod_median": float(np.median(tod)), "tod_mad": float(np.median(np.abs(tod - np.median(tod)))),
            "times": g["ts"].tolist(),
        })
    return pd.DataFrame(out).sort_values(["suspicion", "n"], ascending=[False, False]).reset_index(drop=True) \
        if out else pd.DataFrame()


# ───────────────────────── 🦠 outbreaks ─────────────────────────
def _channel(p: str) -> str:
    if p in REMOTE_PARENTS:
        return "remote"
    if p in EMAIL_PARENTS:
        return "email"
    if p in DEPLOY_PARENTS:
        return "managed"
    if p in USER_PARENTS:
        return "user"
    return "other"


def outbreaks(df: pd.DataFrame, burn_days: float = 3, min_hosts: int = 3) -> list[dict]:
    """Every binary (hash) that was new to the fleet after the burn-in and reached several hosts:
    patient zero, spread curve, channel, and a classification of the spread pattern."""
    d = df[df["sha256"].notna()]
    if d.empty:
        return []
    burn = d["ts"].min() + pd.Timedelta(days=burn_days)
    idx = d.groupby(["sha256", "host"])["ts"].idxmin()
    firsts = d.loc[idx]
    fleet_first = firsts.groupby("sha256")["ts"].min()
    new = fleet_first[fleet_first >= burn].index
    cand = firsts[firsts["sha256"].isin(new)]
    out = []
    for sha, g in cand.groupby("sha256"):
        if g["host"].nunique() < min_hosts:
            continue
        g = g.sort_values("ts")
        t0 = g["ts"].iloc[0]
        hrs = ((g["ts"] - t0).dt.total_seconds() / 3600).to_numpy()
        n = len(g)
        t50 = float(hrs[math.ceil(n / 2) - 1])
        dur = float(hrs[-1])
        ch = g["pname"].map(_channel).value_counts(normalize=True)
        share = {c: float(ch.get(c, 0)) for c in ("remote", "email", "managed", "user", "other")}
        gaps = np.diff(hrs)
        accel = None
        if len(gaps) >= 4:
            h = len(gaps) // 2
            a, b = gaps[:h].mean(), gaps[h:].mean()
            accel = float(a / b) if b > 0 else None
        signed = bool(g["signed"].all())
        if share["remote"] >= 0.5:
            cls = "Worm-like"
            why = "arrived on each new host via a remote-execution service (services.exe / WMI / PsExec)"
            if accel and accel > 1.5:
                why += f", and the spread accelerated ({accel:.1f}× faster in the second half)"
        elif share["email"] >= 0.5 and t50 < 6:
            cls = "Phishing-like"
            why = f"first launched from email/Office apps on {share['email']:.0%} of hosts, half the fleet hit within {human_period(t50 * 3600)}"
        elif share["managed"] >= 0.5:
            cls = "Managed rollout"
            why = "pushed by a deployment/update agent (Windows Update, Intune, SCCM, updaters)"
        elif t50 >= 24:
            cls = "Organic adoption"
            why = f"people started it themselves, one by one; half the hosts took {human_period(t50 * 3600)}"
        else:
            cls = "Unclear"
            why = "mixed launch channels"
        if not signed:
            why += "; the binary is unsigned"
        first = g.iloc[0]
        out.append({
            "sha256": sha, "name": first["name"], "exe": first["exe"], "signed": signed, "signer": first["signer"],
            "hosts": n, "t0": t0, "t50_h": t50, "duration_h": dur, "accel": accel, "share": share, "cls": cls,
            "why": why, "patient_zero": {"host": first["host"], "user": first["user"], "pname": first["pname"],
                                         "cmd": first["cmd"], "ts": t0},
            "curve": pd.DataFrame({"hours": hrs, "hosts": np.arange(1, n + 1), "host": g["host"].to_numpy(),
                                   "user": g["user"].to_numpy(), "pname": g["pname"].to_numpy(),
                                   "ts": g["ts"].to_numpy()}),
        })
    # several binaries arriving together with one spread pattern = one wave
    merged: dict = {}
    for o in out:
        k = (o["cls"], o["hosts"], frozenset(o["curve"]["host"]), round(o["t50_h"] / max(o["t50_h"], 1) * 10))
        if k in merged and abs((merged[k]["t0"] - o["t0"]).total_seconds()) < 6 * 3600:
            merged[k]["names"].append(o["name"])
        else:
            o["names"] = [o["name"]]
            merged[k] = o
    out = list(merged.values())
    order = {"Worm-like": 0, "Phishing-like": 1, "Unclear": 2, "Organic adoption": 3, "Managed rollout": 4}
    return sorted(out, key=lambda o: (order.get(o["cls"], 9), -o["hosts"]))


# ───────────────────────── 📖 grammar ─────────────────────────
def _launches(df: pd.DataFrame, machine_keys: set | None = None) -> pd.DataFrame:
    """Things a person launched: human accounts, not system-parented, not self-spawns (chrome renderers)."""
    g = df[df["human"] & ~df["pname"].isin(SYSTEM_PARENTS) & (df["name"] != df["pname"])]
    if machine_keys:
        key = g["host"] + "|" + g["exe"].str.lower() + "|" + g["cshape"]
        g = g[~key.isin(machine_keys)]
    return g


def grammar(df: pd.DataFrame, machine_keys: set | None = None, gap_min: int = 45) -> dict:
    """Learn each person's 'grammar' of app launches (bigram model with dept/global backoff,
    scored leave-one-day-out) and find the sentences that don't fit."""
    g = _launches(df, machine_keys).sort_values(["user", "host", "ts"])
    if g.empty:
        return {"sessions": [], "workflows": {}, "bigrams": {}}
    new = (g["user"] != g["user"].shift()) | (g["host"] != g["host"].shift()) | \
          ((g["ts"] - g["ts"].shift()) > pd.Timedelta(minutes=gap_min))
    g = g.assign(sid=new.cumsum(), day=g["ts"].dt.date)
    sessions = []
    for sid, s in g.groupby("sid", sort=False):
        sessions.append({"user": s["user"].iloc[0], "host": s["host"].iloc[0], "dept": s["dept"].iloc[0],
                         "day": s["day"].iloc[0], "start": s["ts"].iloc[0], "tokens": s["name"].tolist(),
                         "times": s["ts"].tolist()})

    uu, gu = defaultdict(Counter), Counter()          # unigram: per user, global
    uu_n, gu_n = Counter(), 0
    dayu = defaultdict(Counter)
    uc, uctx = defaultdict(Counter), defaultdict(Counter)
    dc, dctx = defaultdict(Counter), defaultdict(Counter)
    gc, gctx = Counter(), Counter()
    dayc, dayctx = defaultdict(Counter), defaultdict(Counter)
    vocab = set()
    for s in sessions:
        seq = ["<s>"] + s["tokens"]
        vocab.update(s["tokens"])
        for t in s["tokens"]:
            uu[s["user"]][t] += 1; uu_n[s["user"]] += 1; gu[t] += 1; gu_n += 1
            dayu[(s["user"], s["day"])][t] += 1
        for a, b in zip(seq, seq[1:]):
            uc[s["user"]][(a, b)] += 1; uctx[s["user"]][a] += 1
            dc[s["dept"]][(a, b)] += 1; dctx[s["dept"]][a] += 1
            gc[(a, b)] += 1; gctx[a] += 1
            dk = (s["user"], s["day"])
            dayc[dk][(a, b)] += 1; dayctx[dk][a] += 1
    V = len(vocab) + 1

    def prob(a, b, user, dept, day):
        """Interpolated: this person's bigrams, their team's, everyone's, then how common
        app b is at all (for this person, for everyone). Today's own events are left out."""
        dk = (user, day)
        sub, subc = dayc[dk][(a, b)], dayctx[dk][a]
        lv = []
        nu = uctx[user][a] - subc
        if nu > 0:
            lv.append((0.55, (uc[user][(a, b)] - sub) / nu))
        nd = dctx[dept][a] - subc
        if nd > 0:
            lv.append((0.15, (dc[dept][(a, b)] - sub) / nd))
        ng = gctx[a] - subc
        if ng > 0:
            lv.append((0.10, (gc[(a, b)] - sub) / ng))
        du = dayu[dk]
        un = uu_n[user] - sum(du.values())
        if un > 0:
            lv.append((0.10, (uu[user][b] - du[b]) / un))
        gn = gu_n - sum(du.values())
        if gn > 0:
            lv.append((0.09, (gu[b] - du[b]) / gn))
        floor = 0.01
        wsum = sum(w for w, _ in lv) + floor
        return (sum(w * p for w, p in lv) + floor / V) / wsum

    def usual_next(a, user, day):
        dk = (user, day)
        cnt = Counter({b: c - dayc[dk][(a2, b)] for (a2, b), c in uc[user].items() if a2 == a})
        cnt = +cnt
        tot = sum(cnt.values())
        if not tot:
            return None, 0.0
        b, c = cnt.most_common(1)[0]
        return b, c / tot

    for s in sessions:
        seq = ["<s>"] + s["tokens"]
        bits = []
        for a, b in zip(seq, seq[1:]):
            p = prob(a, b, s["user"], s["dept"], s["day"])
            bits.append(-math.log2(max(p, 1e-12)))
        s["bits"] = bits
        i = int(np.argmax(bits)) if bits else 0
        s["max_bits"] = bits[i] if bits else 0.0
        s["worst"] = i
        s["mean_bits"] = float(np.mean(bits)) if bits else 0.0
        s["excess"] = float(sum(max(0.0, b - 7.0) for b in bits))      # surprise beyond 1-in-128, summed
        s["surprising_steps"] = int(sum(b >= 9 for b in bits))
        a = seq[i]
        s["worst_from"], s["worst_to"] = a, seq[i + 1]
        s["usual"], s["usual_p"] = usual_next(a, s["user"], s["day"])
        s["odds"] = int(round(2 ** s["max_bits"]))
    sessions.sort(key=lambda s: (-s["excess"], -s["max_bits"]))

    wf, bg = {}, {}
    for dept in sorted({s["dept"] for s in sessions}):
        tri, bi = Counter(), Counter()
        for s in sessions:
            if s["dept"] != dept:
                continue
            t = s["tokens"]
            tri.update(zip(t, t[1:], t[2:]))
            bi.update(zip(t, t[1:]))
        wf[dept] = tri.most_common(8)
        bg[dept] = bi.most_common(28)
    return {"sessions": sessions, "workflows": wf, "bigrams": bg, "vocab": len(vocab)}


# ───────────────────────── 🗺️ org chart ─────────────────────────
def _unit(M: np.ndarray) -> np.ndarray:
    n = np.linalg.norm(M, axis=-1, keepdims=True)
    n[n == 0] = 1
    return M / n


def org_chart(df: pd.DataFrame, sessions: list[dict], machine_keys: set | None = None, min_launches: int = 40) -> dict:
    """Fingerprint each person (app mix TF-IDF + hour-of-day profile), map everyone in 2D,
    compare to departments, and find sessions that look like somebody else."""
    g = _launches(df, machine_keys)
    counts = g.groupby(["user", "name"]).size().unstack(fill_value=0)
    counts = counts[counts.sum(axis=1) >= min_launches]
    if len(counts) < 3:
        return {}
    users = counts.index.tolist()
    apps = counts.columns.tolist()
    dfreq = (counts > 0).sum(axis=0).to_numpy()
    idf = np.log((1 + len(users)) / (1 + dfreq)) + 1
    X = _unit(np.log1p(counts.to_numpy(float)) * idf)
    hours = g[g["user"].isin(users)].groupby(["user", g["ts"].dt.hour]).size().unstack(fill_value=0)
    hours = hours.reindex(index=users, columns=range(24), fill_value=0).to_numpy(float)
    H = _unit(hours)
    F = _unit(np.hstack([X, 0.35 * H]))
    dept_of = g.groupby("user")["dept"].agg(lambda s: s.mode().iat[0]).reindex(users).tolist()
    C = F - F.mean(axis=0)
    U, S, Vt = np.linalg.svd(C, full_matrices=False)
    xy = U[:, :2] * S[:2]

    depts = sorted(set(dept_of))
    rows = []
    for i, u in enumerate(users):
        sims = {}
        for d in depts:
            members = [j for j, dd in enumerate(dept_of) if dd == d and j != i]
            if not members:
                continue
            c = _unit(F[members].mean(axis=0))
            sims[d] = float(F[i] @ c)
        own = dept_of[i]
        best = max(sims, key=sims.get)
        nearest = sorted(((float(F[i] @ F[j]), users[j]) for j in range(len(users)) if j != i), reverse=True)[:3]
        rows.append({"user": u, "dept": own, "x": float(xy[i, 0]), "y": float(xy[i, 1]), "sims": sims,
                     "best": best, "own_sim": sims.get(own, 0.0), "best_sim": sims[best],
                     "misfit": best != own and sims[best] - sims.get(own, 0) >= 0.04, "nearest": nearest,
                     "top_apps": counts.loc[u].sort_values(ascending=False).head(5).index.tolist()})

    # takeovers: sessions that look like someone else
    col = {a: k for k, a in enumerate(apps)}
    by_user_day = defaultdict(lambda: np.zeros(len(apps)))
    for s in sessions:
        if s["user"] not in counts.index:
            continue
        v = by_user_day[(s["user"], s["day"])]
        for t in s["tokens"]:
            if t in col:
                v[col[t]] += 1
    takeovers = []
    for s in sessions:
        if s["user"] not in counts.index or len(s["tokens"]) < 6:
            continue
        v = np.zeros(len(apps))
        for t in s["tokens"]:
            if t in col:
                v[col[t]] += 1
        sv = _unit(np.log1p(v) * idf)
        own = counts.loc[s["user"]].to_numpy(float) - by_user_day[(s["user"], s["day"])]
        own_v = _unit(np.log1p(np.clip(own, 0, None)) * idf)
        self_sim = float(sv @ own_v)
        best_sim, best_u = -1.0, None
        for j, u in enumerate(users):
            if u == s["user"]:
                continue
            sim = float(sv @ X[j])
            if sim > best_sim:
                best_sim, best_u = sim, u
        if self_sim < 0.45 and best_sim - self_sim >= 0.3:
            takeovers.append({**{k: s[k] for k in ("user", "host", "day", "start", "tokens")},
                              "self_sim": self_sim, "like": best_u, "like_sim": best_sim})
    takeovers.sort(key=lambda t: t["self_sim"] - t["like_sim"])
    return {"people": pd.DataFrame(rows), "takeovers": takeovers, "apps": apps}


# ───────────────────────── 🌅 novelty ─────────────────────────
def novelty(df: pd.DataFrame, burn_days: int = 4, bin_hours: int = 6) -> dict:
    """First-seen curve for three kinds of 'thing'. A healthy fleet learns: novelty decays.
    Spikes after the burn-in are explained (managed update) or not."""
    t_start = df["ts"].min()
    burn = (t_start + pd.Timedelta(days=burn_days)).floor("D")
    kinds = {
        "binary (hash)": df["sha256"].fillna("") ,
        "parent → child": df["pname"] + " → " + df["name"],
        "command shape": df["name"] + "  " + df["cshape"].str.slice(0, 160),
    }
    firsts = []
    for kind, ser in kinds.items():
        d = df.assign(thing=ser)
        d = d[d["thing"] != ""]
        idx = d.groupby("thing")["ts"].idxmin()
        f = d.loc[idx, ["thing", "ts", "host", "user", "name", "pname", "signed", "signer", "exe", "cmd"]]
        hosts = d.groupby("thing")["host"].nunique()
        f = f.assign(kind=kind, hosts=f["thing"].map(hosts))
        firsts.append(f)
    F = pd.concat(firsts, ignore_index=True)
    F["bin"] = F["ts"].dt.floor(f"{bin_hours}h")
    curve = F.groupby(["bin", "kind"]).size().unstack(fill_value=0).sort_index()
    daily = F[F["ts"] >= burn].groupby(F["ts"].dt.floor("D")).size()
    alld = pd.date_range(burn, df["ts"].max().floor("D"), freq="D", tz="UTC")
    daily = daily.reindex(alld, fill_value=0)
    spikes = []
    vals = daily.to_numpy()
    for i, (day, v) in enumerate(daily.items()):
        prev = vals[max(0, i - 5):i]
        base = float(np.median(prev)) if len(prev) >= 2 else float(np.median(vals))
        items = F[(F["ts"].dt.floor("D") == day)]
        hashes = items[items["kind"] == "binary (hash)"]
        unsigned = hashes[~hashes["signed"]]
        spike = v >= max(2.5 * base, base + 10)
        if not (spike or len(unsigned)):
            continue
        managed = float((hashes["pname"].isin(DEPLOY_PARENTS) & hashes["signed"]).mean()) if len(hashes) else 0.0
        explained = len(hashes) > 0 and managed >= 0.8 and unsigned.empty
        top_host, top_share = items["host"].value_counts().index[0], float(items["host"].value_counts(normalize=True).iloc[0])
        top_user = items[items["host"] == top_host]["user"].mode().iat[0]
        kinds_txt = ", ".join(f"{n} {k}" for k, n in items["kind"].value_counts().items())
        if explained:
            label = "Explained — a managed update: new signed binaries pushed by update/deployment services"
        else:
            parts = []
            if len(unsigned):
                parts.append(f"{len(unsigned)} new unsigned binar{'y' if len(unsigned) == 1 else 'ies'} "
                             f"({', '.join(sorted(unsigned['name'].unique())[:3])})")
            if top_share >= 0.4:
                parts.append(f"{top_share:.0%} of it came from one machine: {top_host} ({top_user})")
            label = "Unexplained — " + ("; ".join(parts) if parts else "new behaviours across several machines")
        spikes.append({"day": day, "count": int(v), "baseline": base, "explained": explained, "label": label,
                       "spike": bool(spike), "kinds": kinds_txt, "top_host": top_host, "top_share": top_share,
                       "items": items.sort_values(["signed", "hosts"], ascending=[True, False])})
    learn = F[F["ts"] < burn].shape[0]
    after = F[F["ts"] >= burn].shape[0]
    return {"curve": curve, "daily": daily, "spikes": spikes, "burn": burn, "firsts": F,
            "learned": learn, "after": after}


# ───────────────────────── ⚛️ physics ─────────────────────────
def physics(df: pd.DataFrame, now: pd.Timestamp | None = None) -> dict:
    """Lifecycle oddities from process.start/end + parent links."""
    now = now or df["ts"].max()
    par = df.set_index("eid")[["start", "end", "name", "signed"]].rename(
        columns={"start": "p_start", "end": "p_end", "name": "p_name", "signed": "p_signed"})
    par = par[~par.index.duplicated()]
    c = df[df["peid"].isin(par.index)].join(par, on="peid")
    c_end = c["end"].fillna(now)
    c = c.assign(running=c["end"].isna(),
                 child_life=(c_end - c["start"]).dt.total_seconds(),
                 parent_life=(c["p_end"] - c["p_start"]).dt.total_seconds(),
                 outlived=(c_end - c["p_end"]).dt.total_seconds())
    orph = c[c["p_end"].notna() & (c["outlived"] > 60) & (c["child_life"] > 300)].copy()
    orph["vanish"] = orph["parent_life"] < 3
    orph["flag"] = (~orph["signed"]) | orph["writable"]
    life = ((df["end"].fillna(now) - df["start"]).dt.total_seconds())
    imm = df.assign(life=life, running=df["end"].isna())
    imm = imm[imm["life"] >= 3 * 86400].copy()
    imm["flag"] = (~imm["signed"]) | imm["writable"]
    scatter = c[c["p_end"].notna() & (c["parent_life"] > 0)].copy()
    if len(scatter) > 4000:
        keep = scatter[(scatter["outlived"] > 60)]
        scatter = pd.concat([keep, scatter.drop(keep.index).sample(4000 - min(len(keep), 3999), random_state=1)])
    return {"orphans": orph.sort_values(["flag", "vanish", "child_life"], ascending=False),
            "immortals": imm.sort_values(["flag", "life"], ascending=False), "scatter": scatter,
            "pairs": len(c)}

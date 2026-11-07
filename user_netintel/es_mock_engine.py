"""
es_mock_engine.py - a tiny Elasticsearch emulator over a pandas DataFrame.

It *executes* the query dicts from query_dict.py against the mock events and
returns responses with the same JSON shape Elasticsearch returns
(`hits.hits[]._source`, `aggregations.<name>.buckets[]`, `value`, ...).
Change a query (a size, a filter, a new sub-agg) and the mock response
changes too - so you get real feedback while practising query writing.

Supported (the subset this app needs):
  query : bool(filter/must/must_not/should), term, terms, range (incl. now-7d),
          exists, prefix, wildcard, match, match_all
  aggs  : terms (size, order, include, missing, min_doc_count), multi_terms,
          date_histogram (fixed/calendar interval, time_zone, extended_bounds),
          histogram, filter, filters, sum, avg, min, max, value_count,
          cardinality, stats, percentiles, geo_centroid, top_hits
  hits  : size, sort, _source includes, track_total_hits

Internally columns are numpy arrays (datetime64[ns] UTC, float64, object) so
bucket recursion is just `array.take(positions)` - fast enough for the UI.
"""
from __future__ import annotations

import fnmatch
import math
import re
import time
from typing import Any

import numpy as np
import pandas as pd

_UNITS = {"ms": "ms", "s": "s", "m": "min", "h": "h", "d": "D", "w": "W"}
_NS = {"ms": 10**6, "s": 10**9, "m": 60 * 10**9, "h": 3600 * 10**9, "d": 86400 * 10**9, "w": 7 * 86400 * 10**9}


class Cols:
    """A column-store view: {field: ndarray} plus original row positions."""
    __slots__ = ("c", "pos")

    def __init__(self, c: dict[str, np.ndarray], pos: np.ndarray):
        self.c, self.pos = c, pos

    def __len__(self):
        return len(self.pos)

    def take(self, ix: np.ndarray) -> "Cols":
        return Cols({k: v[ix] for k, v in self.c.items()}, self.pos[ix])

    def get(self, field: str) -> np.ndarray:
        f = field[:-8] if field.endswith(".keyword") else field
        if f in self.c:
            return self.c[f]
        return np.full(len(self.pos), None, dtype=object)


class MockElasticsearch:
    def __init__(self, df: pd.DataFrame):
        self.df = df.reset_index(drop=True)
        self.now = df.attrs.get("now", pd.Timestamp.now(tz="UTC"))
        self.cols = Cols({k: _to_array(self.df[k]) for k in self.df.columns}, np.arange(len(self.df)))

    # ------------------------------------------------------------------ API
    def search(self, index: str = "*", body: dict | None = None, **kw) -> dict:
        body = dict(body or {}, **kw)
        t0 = time.perf_counter()
        mask = self._query(self.cols, body.get("query", {"match_all": {}}))
        ix = np.flatnonzero(mask)
        size = int(body.get("size", 10))
        resp: dict[str, Any] = {
            "took": 0, "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"total": {"value": int(len(ix)), "relation": "eq"}, "max_score": None, "hits": []},
        }
        if size > 0:
            resp["hits"]["hits"] = self._hits(ix, size, body.get("sort"), body.get("_source"))
        aggs = body.get("aggs") or body.get("aggregations")
        if aggs:
            need = {f for c in _fields(aggs) for f in (c, c + ".lat", c + ".lon")} & set(self.cols.c)
            sub = Cols({k: self.cols.c[k][ix] for k in need}, ix)
            resp["aggregations"] = self._aggs(sub, aggs)
        resp["took"] = max(1, int((time.perf_counter() - t0) * 1000))
        return resp

    # ---------------------------------------------------------------- query
    def _time(self, v) -> np.datetime64:
        if isinstance(v, (int, float)):
            t = pd.Timestamp(int(v), unit="ms", tz="UTC")
        else:
            s = str(v)
            m = re.fullmatch(r"now(?:([+-])(\d+)([smhdw]))?(?:/([smhdw]))?", s)
            if m:
                t = self.now
                if m.group(1):
                    delta = pd.Timedelta(int(m.group(2)), unit=_UNITS[m.group(3)])
                    t = t + delta if m.group(1) == "+" else t - delta
                if m.group(4):
                    t = t.floor(_UNITS[m.group(4)])
            else:
                t = pd.Timestamp(s)
                t = t.tz_localize("UTC") if t.tzinfo is None else t.tz_convert("UTC")
        return np.datetime64(t.tz_convert(None).value, "ns")

    def _query(self, cols: Cols, q: dict) -> np.ndarray:
        n = len(cols)
        if not q:
            return np.ones(n, bool)
        (kind, spec), = q.items()
        if kind == "match_all":
            return np.ones(n, bool)
        if kind == "bool":
            m = np.ones(n, bool)
            for key in ("filter", "must"):
                for c in _aslist(spec.get(key)):
                    m &= self._query(cols, c)
            for c in _aslist(spec.get("must_not")):
                m &= ~self._query(cols, c)
            should = _aslist(spec.get("should"))
            if should:
                need = int(spec.get("minimum_should_match", 0 if ("filter" in spec or "must" in spec) else 1))
                if need > 0:
                    cnt = sum(self._query(cols, c).astype(int) for c in should)
                    m &= cnt >= need
            return m
        if kind == "exists":
            return ~pd.isna(cols.get(spec["field"]))
        (field, val), = spec.items()
        a = cols.get(field)
        if kind in ("term", "match"):
            v = val.get("value", val.get("query")) if isinstance(val, dict) else val
            return np.asarray(a == v, dtype=bool)
        if kind == "terms":
            return pd.Index(a).isin(val)
        if kind in ("prefix", "wildcard"):
            v = val.get("value") if isinstance(val, dict) else val
            s = pd.Series(a, dtype="string")
            r = s.str.startswith(v) if kind == "prefix" else s.str.match(fnmatch.translate(v))
            return r.fillna(False).to_numpy(bool)
        if kind == "range":
            m = np.ones(n, bool)
            is_time = a.dtype.kind == "M"
            for op, bound in val.items():
                if op in ("format", "time_zone"):
                    continue
                b = self._time(bound) if is_time else float(bound)
                with np.errstate(invalid="ignore"):
                    m &= {"gte": a >= b, "gt": a > b, "lte": a <= b, "lt": a < b}[op]
            return m
        raise NotImplementedError(f"mock engine: query type '{kind}'")

    # ----------------------------------------------------------------- hits
    def _hits(self, pos: np.ndarray, size: int, sort, src) -> list[dict]:
        df = self.df.iloc[pos]
        if sort:
            keys, asc = [], []
            for s in _aslist(sort):
                k, o = (s, "asc") if isinstance(s, str) else next(iter(s.items()))
                if k in df.columns:
                    keys.append(k)
                    asc.append((o.get("order", "asc") if isinstance(o, dict) else o) == "asc")
            if keys:
                df = df.sort_values(keys, ascending=asc, na_position="last", kind="stable")
        df = df.head(size)
        includes = src.get("includes") if isinstance(src, dict) else (src if isinstance(src, list) else None)
        return [{"_index": ".ds-logs-network-mock", "_id": f"mock-{i}", "_score": None,
                 "_source": _unflatten(row, includes)} for i, row in zip(df.index, df.to_dict("records"))]

    # ----------------------------------------------------------------- aggs
    def _aggs(self, cols: Cols, aggs: dict) -> dict:
        return {name: self._agg(cols, spec) for name, spec in (aggs or {}).items()}

    def _agg(self, cols: Cols, spec: dict) -> dict:
        sub_aggs = spec.get("aggs") or spec.get("aggregations")
        kind = next(k for k in spec if k not in ("aggs", "aggregations", "meta"))
        p = spec[kind]

        if kind in ("sum", "avg", "min", "max", "value_count", "cardinality", "stats", "percentiles", "geo_centroid"):
            return self._metric(cols, kind, p)
        if kind == "top_hits":
            return {"hits": {"total": {"value": len(cols), "relation": "eq"},
                             "hits": self._hits(cols.pos, int(p.get("size", 3)), p.get("sort"), p.get("_source"))}}
        if kind == "filter":
            sub = cols.take(np.flatnonzero(self._query(cols, p)))
            return {"doc_count": len(sub), **(self._aggs(sub, sub_aggs) if sub_aggs else {})}
        if kind == "filters":
            out = {}
            for k, q in p["filters"].items():
                sub = cols.take(np.flatnonzero(self._query(cols, q)))
                out[k] = {"doc_count": len(sub), **(self._aggs(sub, sub_aggs) if sub_aggs else {})}
            return {"buckets": out}
        if kind == "terms":
            a = cols.get(p["field"])
            if "missing" in p:
                a = a.astype(object)
                a[pd.isna(a)] = p["missing"]
            groups = _group([a])
            if isinstance(p.get("include"), str):
                rx = re.compile(p["include"])
                groups = [(k, ix) for k, ix in groups if rx.fullmatch(str(k[0]))]
            return self._buckets(cols, groups, p, sub_aggs, single=True)
        if kind == "multi_terms":
            return self._buckets(cols, _group([cols.get(t["field"]) for t in p["terms"]]), p, sub_aggs, single=False)
        if kind == "date_histogram":
            return self._date_hist(cols, p, sub_aggs)
        if kind == "histogram":
            a = cols.get(p["field"]).astype(float)
            iv = float(p["interval"])
            out = []
            for (k,), ix in sorted(_group([np.floor(a / iv) * iv]), key=lambda g: g[0][0]):
                sub = cols.take(ix)
                out.append({"key": float(k), "doc_count": len(sub), **(self._aggs(sub, sub_aggs) if sub_aggs else {})})
            return {"buckets": [b for b in out if b["doc_count"] >= int(p.get("min_doc_count", 0))]}
        raise NotImplementedError(f"mock engine: agg type '{kind}'")

    def _metric(self, cols: Cols, kind: str, p: dict) -> dict:
        if kind == "geo_centroid":
            lat = cols.get(p["field"] + ".lat").astype(float)
            lon = cols.get(p["field"] + ".lon").astype(float)
            ok = ~(np.isnan(lat) | np.isnan(lon))
            if not ok.any():
                return {"count": 0}
            return {"location": {"lat": float(lat[ok].mean()), "lon": float(lon[ok].mean())}, "count": int(ok.sum())}
        a = cols.get(p["field"])
        valid = a[~pd.isna(a)]
        if kind == "cardinality":
            return {"value": int(len(pd.unique(valid)))}
        if kind == "value_count":
            return {"value": int(len(valid))}
        if a.dtype.kind == "M":
            if not len(valid):
                return {"value": None}
            v = pd.Timestamp(valid.min() if kind == "min" else valid.max(), tz="UTC")
            return {"value": float(v.value // 10**6), "value_as_string": v.isoformat().replace("+00:00", "Z")}
        num = valid.astype(float)
        if kind == "sum":
            return {"value": float(num.sum())}
        if kind in ("avg", "min", "max"):
            return {"value": float({"avg": np.mean, "min": np.min, "max": np.max}[kind](num)) if len(num) else None}
        if kind == "stats":
            if not len(num):
                return {"count": 0, "min": None, "max": None, "avg": None, "sum": 0.0}
            return {"count": int(len(num)), "min": float(num.min()), "max": float(num.max()),
                    "avg": float(num.mean()), "sum": float(num.sum())}
        if kind == "percentiles":
            pcts = p.get("percents", [1, 5, 25, 50, 75, 95, 99])
            return {"values": {str(float(q)): (float(np.percentile(num, q)) if len(num) else None) for q in pcts}}
        raise NotImplementedError(kind)

    def _buckets(self, cols, groups, p, sub_aggs, single: bool):
        mdc = int(p.get("min_doc_count", 1))
        size = int(p.get("size", 10))
        order = _aslist(p.get("order", {"_count": "desc"}))
        sort_by_sub = any(next(iter(o)) not in ("_count", "_key", "_term") for o in order)
        groups = [g for g in groups if len(g[1]) >= mdc]
        if not sort_by_sub:  # cheap: order & truncate before computing sub-aggs
            groups = _order(groups, order, lambda g, k: len(g[1]) if k == "_count" else str(g[0][0]))
            kept_groups = groups[:size]
        else:
            kept_groups = groups
        buckets = []
        for key, ix in kept_groups:
            b = {"key": _py(key[0]) if single else [_py(k) for k in key], "doc_count": int(len(ix))}
            if not single:
                b["key_as_string"] = "|".join(str(_py(k)) for k in key)
            if sub_aggs:
                b.update(self._aggs(cols.take(ix), sub_aggs))
            buckets.append(b)
        if sort_by_sub:
            buckets = _order(buckets, order, _sort_val)[:size]
        total = sum(len(g[1]) for g in groups)
        return {"doc_count_error_upper_bound": 0,
                "sum_other_doc_count": int(total - sum(b["doc_count"] for b in buckets)), "buckets": buckets}

    def _date_hist(self, cols, p, sub_aggs):
        iv = p.get("fixed_interval") or p.get("calendar_interval") or p.get("interval")
        unit_n, unit = _interval(iv)
        tz = p.get("time_zone")
        a = cols.get(p["field"])
        ok = ~pd.isna(a)
        if tz and unit in ("d", "w"):
            idx = pd.DatetimeIndex(a[ok]).tz_localize("UTC").tz_convert(tz).tz_localize(None).floor("D")
            keys_ns = idx.tz_localize(tz, ambiguous=False, nonexistent="shift_forward").tz_convert(None).asi8
            step = None
        else:
            step = unit_n * _NS[unit]
            keys_ns = (a[ok].astype("int64") // step) * step
        pos = np.flatnonzero(ok)
        grouped = {k: pos[ix] for (k,), ix in _group([keys_ns])}
        mdc = int(p.get("min_doc_count", 0))
        keys = sorted(grouped)
        if mdc == 0 and step:
            eb = p.get("extended_bounds")
            lo = self._time(eb["min"]).astype("int64") if eb else (keys[0] if keys else None)
            hi = self._time(eb["max"]).astype("int64") if eb else (keys[-1] if keys else None)
            if lo is not None:
                keys = sorted(set(range((lo // step) * step, (hi // step) * step + 1, step)) | set(keys))
        out = []
        empty = np.array([], dtype=int)
        for k in keys:
            ix = grouped.get(k, empty)
            if len(ix) < mdc:
                continue
            ts = pd.Timestamp(int(k), tz="UTC")
            if tz:
                ts = ts.tz_convert(tz)
            b = {"key_as_string": ts.isoformat(), "key": int(k // 10**6), "doc_count": int(len(ix))}
            if sub_aggs:
                b.update(self._aggs(cols.take(ix), sub_aggs))
            out.append(b)
        return {"buckets": out}


# ---------------------------------------------------------------- helpers
def _to_array(s: pd.Series) -> np.ndarray:
    if pd.api.types.is_datetime64_any_dtype(s):
        return s.dt.tz_convert("UTC").dt.tz_localize(None).to_numpy("datetime64[ns]")
    if pd.api.types.is_numeric_dtype(s) and not pd.api.types.is_bool_dtype(s):
        return s.to_numpy(float, na_value=np.nan)
    if s.dtype == object or pd.api.types.is_string_dtype(s):
        nn = s.dropna()
        if len(nn) and all(isinstance(x, (int, float, np.integer, np.floating)) and not isinstance(x, bool)
                           for x in nn.iloc[:200]):
            return pd.to_numeric(s, errors="coerce").to_numpy(float, na_value=np.nan)
    return s.astype(object).where(s.notna(), None).to_numpy(object)


def _group(arrays: list[np.ndarray]) -> list[tuple[tuple, np.ndarray]]:
    """Group row positions by the combination of keys (nulls dropped)."""
    n = len(arrays[0])
    if n == 0:
        return []
    valid = np.ones(n, bool)
    codes, uniqs = [], []
    for a in arrays:
        valid &= ~pd.isna(a)
    pos = np.flatnonzero(valid)
    if not len(pos):
        return []
    for a in arrays:
        c, u = pd.factorize(a[pos], sort=False)
        codes.append(c)
        uniqs.append(np.asarray(u, dtype=object))
    combo = codes[0].astype(np.int64)
    for c, u in zip(codes[1:], uniqs[1:]):
        combo = combo * len(u) + c
    order = np.argsort(combo, kind="stable")
    sc = combo[order]
    cut = np.flatnonzero(np.diff(sc)) + 1
    out = []
    for chunk in np.split(order, cut):
        first = chunk[0]
        out.append((tuple(u[c[first]] for c, u in zip(codes, uniqs)), pos[chunk]))
    return out


def _order(items, order, keyfn):
    for o in reversed(order):
        (k, d), = o.items()
        items = sorted(items, key=lambda it: keyfn(it, k), reverse=(d == "desc"))
    return items


def _fields(obj) -> set[str]:
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "field" and isinstance(v, str):
                out.add(v)
            elif k in ("term", "terms", "range", "prefix", "wildcard", "match") and isinstance(v, dict):
                out |= set(v)
            out |= _fields(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _fields(v)
    return out


def _aslist(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _interval(iv: str) -> tuple[int, str]:
    m = re.fullmatch(r"(\d*)(ms|[smhdw])", iv)
    if m:
        return int(m.group(1) or 1), m.group(2)
    named = {"minute": "m", "hour": "h", "day": "d", "week": "w"}
    if iv in named:
        return 1, named[iv]
    raise ValueError(f"bad interval {iv}")


def _py(v):
    if isinstance(v, np.integer):
        return int(v)
    if isinstance(v, (float, np.floating)):
        return int(v) if float(v).is_integer() else float(v)
    if isinstance(v, np.datetime64):
        return int(v.astype("int64") // 10**6)
    return v


def _sort_val(b, k):
    if k == "_count":
        return b["doc_count"]
    if k in ("_key", "_term"):
        return str(b["key"])
    head, _, tail = k.partition(".")
    v = b.get(head, {})
    if isinstance(v, dict):
        v = v.get(tail) if tail else v.get("value", v.get("doc_count"))
    return v if v is not None else -math.inf


def _unflatten(row: dict, includes) -> dict:
    out: dict = {}
    for k, v in row.items():
        if v is None or v is pd.NaT or (isinstance(v, float) and math.isnan(v)):
            continue
        if includes and not any(k == i or fnmatch.fnmatch(k, i) or k.startswith(i.rstrip("*").rstrip(".") + ".")
                                for i in includes):
            continue
        if isinstance(v, pd.Timestamp):
            v = v.isoformat().replace("+00:00", "Z")
        elif isinstance(v, np.generic):
            v = v.item()
        parts = k.split(".")
        d = out
        for part in parts[:-1]:
            nxt = d.setdefault(part, {})
            if not isinstance(nxt, dict):
                break
            d = nxt
        else:
            d[parts[-1]] = v
    return out

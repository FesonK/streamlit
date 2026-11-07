"""
data_source.py - the ONE place that knows where data comes from.

    search(body)  -> Elasticsearch-shaped response dict

Mock mode (default): the query is executed by es_mock_engine against the
synthetic events in mock_data.py.

Real mode: set environment variables and the exact same query dicts go to your
cluster - nothing else in the app changes.
    NETINTEL_ES_URL=https://my-cluster:9200
    NETINTEL_ES_API_KEY=xxxx            (or NETINTEL_ES_USER / NETINTEL_ES_PASSWORD)
    NETINTEL_ES_INDEX=logs-network_traffic.*,logs-vpn.*   (optional)
"""
from __future__ import annotations

import os
from functools import lru_cache

import query_dict as Q

ES_URL = os.getenv("NETINTEL_ES_URL")
MODE = "elasticsearch" if ES_URL else "mock"


@lru_cache(maxsize=1)
def _client():
    if MODE == "mock":
        from es_mock_engine import MockElasticsearch
        from mock_data import build_events
        return MockElasticsearch(build_events())
    from elasticsearch import Elasticsearch  # pip install elasticsearch
    kw = {}
    if os.getenv("NETINTEL_ES_API_KEY"):
        kw["api_key"] = os.environ["NETINTEL_ES_API_KEY"]
    elif os.getenv("NETINTEL_ES_USER"):
        kw["basic_auth"] = (os.environ["NETINTEL_ES_USER"], os.environ.get("NETINTEL_ES_PASSWORD", ""))
    return Elasticsearch(ES_URL, **kw)


def search(body: dict, index: str | None = None) -> dict:
    index = index or os.getenv("NETINTEL_ES_INDEX", Q.INDEX)
    client = _client()
    if MODE == "mock":
        return client.search(index=index, body=body)
    return client.search(index=index, **body).body


def now():
    """'Now' as the data sees it (mock data is generated relative to its own clock)."""
    import pandas as pd
    if MODE == "mock":
        return _client().now
    return pd.Timestamp.now(tz="UTC")

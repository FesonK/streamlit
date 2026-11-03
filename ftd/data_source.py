"""
data_source.py — the single switch between mock data and a real cluster.

  FTD_MODE=mock     (default) answers come from mock_responses.MockElastic
  FTD_MODE=elastic  real cluster, configured with either
                      ES_URL=https://host:9200  [+ ES_API_KEY=...]
                      ES_CLOUD_ID=...           [+ ES_API_KEY=...]

The app only calls DataSource.search / fetch_all, so swapping is one env var.
"""
from __future__ import annotations

import os

from query_dict import QUERIES


class DataSource:
    def __init__(self) -> None:
        self.mode = os.getenv("FTD_MODE", "mock").lower()
        self._mock = None
        self._es = None
        if self.mode == "elastic":
            from elasticsearch import Elasticsearch  # pip install elasticsearch

            kwargs = {"api_key": os.environ["ES_API_KEY"]} if os.getenv("ES_API_KEY") else {}
            if os.getenv("ES_CLOUD_ID"):
                self._es = Elasticsearch(cloud_id=os.environ["ES_CLOUD_ID"], **kwargs)
                self.target = "Elastic Cloud"
            else:
                url = os.getenv("ES_URL", "http://localhost:9200")
                self._es = Elasticsearch(url, **kwargs)
                self.target = url
        else:
            from mock_responses import MockElastic

            self._mock = MockElastic()
            self.target = "mock"

    @property
    def is_mock(self) -> bool:
        return self._mock is not None

    def search(self, name: str, **params) -> tuple[dict, dict]:
        """Build the named query and run it. Returns (request, response)."""
        req = QUERIES[name](**params)
        if self._mock is not None:
            resp = self._mock.respond(name, params)
        else:
            resp = self._es.search(index=req["index"], **req["body"])
            resp = getattr(resp, "body", resp)
        return req, resp

    def fetch_all(self, name: str, max_docs: int = 20_000, **params) -> tuple[list[dict], list[dict], bool]:
        """Page through a sorted query with search_after.
        Returns (requests_sent, hits, truncated)."""
        reqs: list[dict] = []
        hits: list[dict] = []
        after = None
        while len(hits) < max_docs:
            req, resp = self.search(name, search_after=after, **params)
            reqs.append(req)
            page = resp["hits"]["hits"]
            hits.extend(page)
            if len(page) < req["body"]["size"]:
                return reqs, hits, False
            after = page[-1]["sort"]
        return reqs, hits[:max_docs], True

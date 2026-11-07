"""
data_source.py — the one switch between mock data and a real cluster.

  FTD_MODE=mock     (default) answers come from mock_responses.MockElastic
  FTD_MODE=elastic  real cluster via ES_URL [+ ES_API_KEY] or ES_CLOUD_ID
"""
from __future__ import annotations

import os

from query_dict import QUERIES


class DataSource:
    def __init__(self):
        self.mode = os.getenv("FTD_MODE", "mock").lower()
        self._mock = self._es = None
        if self.mode == "elastic":
            from elasticsearch import Elasticsearch
            kw = {"api_key": os.environ["ES_API_KEY"]} if os.getenv("ES_API_KEY") else {}
            if os.getenv("ES_CLOUD_ID"):
                self._es, self.target = Elasticsearch(cloud_id=os.environ["ES_CLOUD_ID"], **kw), "Elastic Cloud"
            else:
                url = os.getenv("ES_URL", "http://localhost:9200")
                self._es, self.target = Elasticsearch(url, **kw), url
        else:
            from mock_responses import MockElastic
            self._mock, self.target = MockElastic(), "mock"

    @property
    def is_mock(self):
        return self._mock is not None

    def search(self, name, **params):
        req = QUERIES[name](**params)
        if self._mock is not None:
            return req, self._mock.respond(name, params)
        resp = self._es.search(index=req["index"], **req["body"])
        return req, getattr(resp, "body", resp)

    def fetch_all(self, name, max_docs=250_000, **params):
        reqs, hits, after = [], [], None
        while len(hits) < max_docs:
            req, resp = self.search(name, search_after=after, **params)
            reqs.append(req)
            page = resp["hits"]["hits"]
            hits.extend(page)
            if len(page) < req["body"]["size"]:
                return reqs, hits, False
            after = page[-1]["sort"]
        return reqs, hits[:max_docs], True

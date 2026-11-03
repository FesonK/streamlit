"""
train_score.py — fit the obfuscation score (Revoke-Obfuscation in miniature).

Logistic regression over the syntax-tree features in psparse.features, trained
on clean scripts in two forms: plain (0) and machine-obfuscated (1). Pure numpy,
no dependencies. Writes score_model.json (weights + feature means/stds).

    python train_score.py          # train, cross-validate, save
"""
from __future__ import annotations

import json
import random

import numpy as np

from corpus import clean_samples
from obfuscator import obfuscate
from psparse import FEATURES, features, peel

OUT = "score_model.json"


def build_dataset(seed: int = 0):
    rng = random.Random(seed)
    clean = clean_samples()
    X, y = [], []
    for i, src in enumerate(clean):
        # plain form → label 0, several times so counts stay balanced
        for _ in range(3):
            X.append([features(src)[f] for f in FEATURES])
            y.append(0)
        # obfuscated forms → label 1, varied intensity
        for _ in range(3):
            lvl = rng.uniform(0.4, 0.95)
            obf = obfuscate(src, rng, level=lvl, wrap_b64=0.15)
            X.append([features(obf)[f] for f in FEATURES])
            y.append(1)
    return np.array(X, float), np.array(y, float)


def _standardize(X, mu, sd):
    return (X - mu) / sd


def fit(X, y, l2=1.0, epochs=4000, lr=0.3):
    mu, sd = X.mean(0), X.std(0) + 1e-9
    Xs = _standardize(X, mu, sd)
    n, d = Xs.shape
    w, b = np.zeros(d), 0.0
    for _ in range(epochs):
        z = Xs @ w + b
        p = 1 / (1 + np.exp(-z))
        g = p - y
        gw = Xs.T @ g / n + l2 * w / n
        gb = g.mean()
        w -= lr * gw
        b -= lr * gb
    return w, b, mu, sd


def cross_val(X, y, k=5):
    idx = np.arange(len(y))
    rng = np.random.default_rng(1)
    rng.shuffle(idx)
    folds = np.array_split(idx, k)
    accs, aucs = [], []
    for i in range(k):
        te = folds[i]
        tr = np.concatenate([folds[j] for j in range(k) if j != i])
        w, b, mu, sd = fit(X[tr], y[tr])
        p = 1 / (1 + np.exp(-(_standardize(X[te], mu, sd) @ w + b)))
        accs.append(float((( p > 0.5) == y[te]).mean()))
        # AUC via rank statistic
        pos, neg = p[y[te] == 1], p[y[te] == 0]
        if len(pos) and len(neg):
            wins = sum((pos[:, None] > neg[None, :]).sum() + 0.5 * (pos[:, None] == neg[None, :]).sum()
                       for _ in [0]) / (len(pos) * len(neg))
            aucs.append(float(wins))
    return np.mean(accs), np.mean(aucs)


def main():
    X, y = build_dataset()
    acc, auc = cross_val(X, y)
    print(f"dataset: {len(y)} samples, {int(y.sum())} obfuscated")
    print(f"5-fold cross-val  accuracy={acc:.3f}  AUC={auc:.3f}")
    w, b, mu, sd = fit(X, y)
    model = {
        "features": FEATURES,
        "w": w.tolist(), "b": float(b),
        "mu": mu.tolist(), "sd": sd.tolist(),
        "cv_accuracy": round(acc, 4), "cv_auc": round(auc, 4),
    }
    json.dump(model, open(OUT, "w"), indent=2)
    print(f"saved {OUT}")
    order = sorted(zip(FEATURES, w), key=lambda t: -abs(t[1]))
    print("weights (standardized):")
    for f, wi in order:
        print(f"  {f:16s} {wi:+.3f}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import numpy as np


class MappedKMeansClassifier:
    """Wrap KMeans so cluster ids are mapped to encoded class labels."""

    def __init__(self, kmeans, cluster_to_label):
        self.kmeans = kmeans
        self.cluster_to_label = dict(cluster_to_label)

    def predict(self, X):
        clusters = self.kmeans.predict(X)
        return np.array([self.cluster_to_label[int(cluster)] for cluster in clusters], dtype=int)

    def predict_proba(self, X):
        distances = self.kmeans.transform(X)
        similarities = 1.0 / (distances + 1e-9)
        cluster_probs = similarities / similarities.sum(axis=1, keepdims=True)

        n_classes = len(set(self.cluster_to_label.values()))
        probs = np.zeros((len(cluster_probs), n_classes), dtype=float)
        for cluster_id, label_id in self.cluster_to_label.items():
            probs[:, int(label_id)] += cluster_probs[:, int(cluster_id)]
        return probs

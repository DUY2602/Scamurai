import { useEffect, useState } from "react";
import { getApiErrorMessage, getDashboard, getMetrics } from "../api/scamurai_api";
import MetricsPanel from "../components/MetricsPanel";
import PageHeader from "../components/PageHeader";

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function formatLabel(label) {
  return label
    .replace(/_/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatValue(value, key = "") {
  const normalizedKey = key.toLowerCase();

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (typeof value === "number") {
    const shouldFormatAsPercent = [
      "score",
      "prob",
      "ratio",
      "accuracy",
      "precision",
      "recall",
      "f1",
    ].some((token) => normalizedKey.includes(token));

    if (shouldFormatAsPercent) {
      const percentValue = value <= 1 ? value * 100 : value;
      return `${percentValue.toFixed(percentValue >= 10 ? 1 : 2)}%`;
    }

    return Number.isInteger(value)
      ? value.toLocaleString()
      : value.toFixed(value >= 10 ? 1 : 4).replace(/\.?0+$/, "");
  }

  return String(value);
}

function findNumber(source, aliases) {
  if (!isPlainObject(source)) {
    return undefined;
  }

  for (const alias of aliases) {
    if (typeof source[alias] === "number") {
      return source[alias];
    }
  }

  return undefined;
}

function getSummary(stats) {
  const source = stats?.summary || stats?.overview || stats?.totals || stats || {};

  return {
    total:
      findNumber(source, ["total_scans", "total", "scan_count", "scans"]) ?? 0,
    malicious:
      findNumber(source, ["malicious_count", "malicious", "danger_count"]) ?? 0,
    suspicious:
      findNumber(source, ["suspicious_count", "suspicious", "warning_count"]) ?? 0,
    safe: findNumber(source, ["safe_count", "safe", "benign", "clean", "ham"]) ?? 0,
  };
}

function getTypeStats(stats, type) {
  return (
    stats?.[type] ||
    stats?.by_type?.[type] ||
    stats?.per_type?.[type] ||
    stats?.types?.[type] ||
    null
  );
}

function getReadableEntries(source) {
  if (!isPlainObject(source)) {
    return [];
  }

  return Object.entries(source).filter(([, value]) => {
    if (value === null || value === undefined || value === "") {
      return false;
    }

    return !Array.isArray(value) && !isPlainObject(value);
  });
}

export default function Dashboard() {
  const [stats, setStats] = useState({});
  const [metrics, setMetrics] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadDashboardData() {
    setLoading(true);
    setError("");

    const [statsResult, metricsResult] = await Promise.allSettled([
      getDashboard(),
      getMetrics(),
    ]);

    const messages = [];

    if (statsResult.status === "fulfilled" && statsResult.value) {
      setStats(statsResult.value);
    } else if (statsResult.status === "rejected") {
      messages.push(getApiErrorMessage(statsResult.reason, "Could not load dashboard stats."));
      setStats({});
    }

    if (metricsResult.status === "fulfilled" && metricsResult.value) {
      setMetrics(metricsResult.value);
    } else if (metricsResult.status === "rejected") {
      messages.push(getApiErrorMessage(metricsResult.reason, "Could not load model metrics."));
      setMetrics({});
    }

    setError(messages.join(" "));
    setLoading(false);
  }

  useEffect(() => {
    loadDashboardData();
  }, []);

  const summary = getSummary(stats);
  const typeCards = ["url", "file", "email"]
    .map((type) => ({
      type,
      entries: getReadableEntries(getTypeStats(stats, type)),
    }))
    .filter((item) => item.entries.length > 0);

  return (
    <div className="page-shell page">
      <PageHeader
        actions={
          <button className="btn btn--secondary" onClick={loadDashboardData} type="button">
            Refresh
          </button>
        }
        description="This page combines scan summaries and model metrics. It also stays graceful when the backend still returns zeros or empty objects."
        eyebrow="Dashboard"
        title="Monitor scan counts and model health"
      />

      {error ? <div className="feedback feedback--error">{error}</div> : null}

      <section className="grid grid--four">
        <article className="summary-card summary-card--primary">
          <p className="summary-card__label">Total scans</p>
          <p className="summary-card__value">{loading ? "..." : summary.total}</p>
        </article>
        <article className="summary-card summary-card--danger">
          <p className="summary-card__label">Malicious count</p>
          <p className="summary-card__value">{loading ? "..." : summary.malicious}</p>
        </article>
        <article className="summary-card summary-card--warning">
          <p className="summary-card__label">Suspicious count</p>
          <p className="summary-card__value">{loading ? "..." : summary.suspicious}</p>
        </article>
        <article className="summary-card summary-card--safe">
          <p className="summary-card__label">Safe count</p>
          <p className="summary-card__value">{loading ? "..." : summary.safe}</p>
        </article>
      </section>

      <section className="panel">
        <h2 className="panel__title">Per-type scan stats</h2>
        <p className="panel__description">
          URL, file, and email stats appear here when the backend provides them.
        </p>

        {typeCards.length ? (
          <div className="grid grid--three" style={{ marginTop: "1rem" }}>
            {typeCards.map((card) => (
              <article className="metric-card" key={card.type}>
                <h4>{formatLabel(card.type)}</h4>
                <div className="metric-list">
                  {card.entries.map(([key, value]) => (
                    <div className="metric-row" key={`${card.type}-${key}`}>
                      <span className="metric-row__label">{formatLabel(key)}</span>
                      <span className="metric-row__value">{formatValue(value, key)}</span>
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <div className="empty-card" style={{ marginTop: "1rem" }}>
            <h3>No per-type stats yet</h3>
            <p>
              Once the backend returns URL, file, or email buckets, Scamurai will
              render them as compact cards here.
            </p>
          </div>
        )}
      </section>

      <section className="panel">
        <h2 className="panel__title">Model metrics</h2>
        <p className="panel__description">
          Metrics are grouped into compact cards so the dashboard stays easy to
          read during demos.
        </p>

        <div style={{ marginTop: "1rem" }}>
          <MetricsPanel metrics={metrics} />
        </div>
      </section>
    </div>
  );
}

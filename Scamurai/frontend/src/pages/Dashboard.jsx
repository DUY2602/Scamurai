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

function formatDateLabel(value) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}

function formatDateTime(value) {
  if (!value) {
    return "Unknown time";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function truncateValue(value, maxLength = 64) {
  if (!value) {
    return "No source value";
  }

  const normalized = String(value);
  return normalized.length > maxLength
    ? `${normalized.slice(0, maxLength - 1)}...`
    : normalized;
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
  const dataSource = stats?.data_source || "unknown";
  const typeCards = ["url", "file", "email"]
    .map((type) => ({
      type,
      entries: getReadableEntries(getTypeStats(stats, type)),
    }))
    .filter((item) => item.entries.length > 0);
  const trendRows = Array.isArray(stats?.trend) ? stats.trend : [];
  const topCountries = Array.isArray(stats?.top_countries) ? stats.top_countries : [];
  const recentDetections = Array.isArray(stats?.recent_detections)
    ? stats.recent_detections
    : [];

  return (
    <div className="page-shell page">
      <PageHeader
        actions={
          <button className="btn btn--secondary" onClick={loadDashboardData} type="button">
            Refresh
          </button>
        }
        description={`This dashboard now reads live detection history from the backend database when available. Current source: ${dataSource}.`}
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

      <section className="grid grid--two">
        <article className="panel">
          <h2 className="panel__title">7-day detection trend</h2>
          <p className="panel__description">
            Daily totals come from the database. Total scans and threats are shown side by side.
          </p>

          {trendRows.length ? (
            <div className="metric-list" style={{ marginTop: "1rem" }}>
              {trendRows.map((row) => (
                <div className="metric-row" key={row.day}>
                  <span className="metric-row__label">{formatDateLabel(row.day)}</span>
                  <span className="metric-row__value">
                    {row.total_scans} total / {row.threat_count} threats
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-card" style={{ marginTop: "1rem" }}>
              <h3>No trend data yet</h3>
              <p>Run a few detections and the database-backed trend view will fill in.</p>
            </div>
          )}
        </article>

        <article className="panel">
          <h2 className="panel__title">Top countries</h2>
          <p className="panel__description">
            These countries are inferred from request IP geolocation captured during scans.
          </p>

          {topCountries.length ? (
            <div className="metric-list" style={{ marginTop: "1rem" }}>
              {topCountries.map((country) => (
                <div
                  className="metric-row"
                  key={`${country.country_code || "xx"}-${country.country_name || "unknown"}`}
                >
                  <span className="metric-row__label">
                    {country.country_name || "Unknown"}
                  </span>
                  <span className="metric-row__value">
                    {country.total_scans} scans / {country.threat_count} threats
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-card" style={{ marginTop: "1rem" }}>
              <h3>No country data yet</h3>
              <p>
                Once requests come from public IPs and database logging is active, country
                totals will appear here.
              </p>
            </div>
          )}
        </article>
      </section>

      <section className="panel">
        <h2 className="panel__title">Recent detections</h2>
        <p className="panel__description">
          Latest records stored in the database, including status and risk score.
        </p>

        {recentDetections.length ? (
          <div className="metric-list" style={{ marginTop: "1rem" }}>
            {recentDetections.map((item) => (
              <div className="metric-row metric-row--stack" key={item.id}>
                <div>
                  <div className="metric-row__value">
                    {formatLabel(item.detection_type)} / {item.verdict || item.status}
                  </div>
                  <div className="metric-row__label">
                    {truncateValue(item.source_value)}
                  </div>
                </div>
                <div className="dashboard-meta">
                  <span>{item.risk_score ?? 0}%</span>
                  <span>{item.country_name || "Unknown country"}</span>
                  <span>{formatDateTime(item.created_at)}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-card" style={{ marginTop: "1rem" }}>
            <h3>No detections stored yet</h3>
            <p>As soon as database inserts start landing, the latest scan history will show up here.</p>
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

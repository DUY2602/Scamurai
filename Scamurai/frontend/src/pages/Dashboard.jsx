import { useEffect, useRef, useState } from "react";
import {
  getApiErrorMessage,
  getDashboard,
  getDatasetInsights,
} from "../api/scamurai_api";
import PageHeader from "../components/PageHeader";
import ThreatMap from "../components/ThreatMap";

const TOPIC_OPTIONS = [
  { id: "url", label: "URL" },
  { id: "file", label: "File" },
  { id: "email", label: "Email" },
];

const MAP_TOPIC_OPTIONS = [
  { id: "all", label: "All" },
  { id: "url", label: "URL" },
  { id: "file", label: "File" },
  { id: "email", label: "Email" },
];

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

function formatTrendAxisLabel(value, compact = false) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleDateString(undefined, compact
    ? { month: "short", day: "numeric" }
    : { day: "numeric" });
}

function buildTrendXAxisTicks(rows) {
  const total = rows.length;

  if (!total) {
    return [];
  }

  const targetTickCount =
    total > 28 ? 6 : total > 14 ? 7 : total > 8 ? 6 : total;
  const step = Math.max(1, Math.ceil((total - 1) / Math.max(targetTickCount - 1, 1)));

  return rows.map((row, index) => {
    const currentDate = new Date(row.day);
    const previousDate = index > 0 ? new Date(rows[index - 1].day) : null;
    const isBoundary =
      index === 0 ||
      index === total - 1 ||
      index % step === 0;
    const crossedMonth =
      previousDate &&
      !Number.isNaN(currentDate.getTime()) &&
      !Number.isNaN(previousDate.getTime()) &&
      currentDate.getMonth() !== previousDate.getMonth();
    const showLabel = total <= 8 || isBoundary || crossedMonth;

    return {
      key: row.day || `tick-${index}`,
      showLabel,
      label: showLabel ? formatTrendAxisLabel(row.day, true) : "",
      textAnchor: index === 0 ? "start" : index === total - 1 ? "end" : "middle",
    };
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

function formatCountryCode(value) {
  return String(value || "N/A").toUpperCase();
}

function getThreatRateColor(threatRatio) {
  if (threatRatio >= 60) {
    return "#dc2626";
  }

  if (threatRatio >= 30) {
    return "#f59e0b";
  }

  return "#16a34a";
}

function buildTrendTicks(maxValue) {
  const safeMax = Math.max(1, Number(maxValue || 0));

  if (safeMax <= 5) {
    return Array.from({ length: safeMax + 1 }, (_, index) => index);
  }

  const roughStep = safeMax / 4;
  const magnitude = 10 ** Math.floor(Math.log10(Math.max(roughStep, 1)));
  const normalized = roughStep / magnitude;

  let niceStep = 1;
  if (normalized <= 1) {
    niceStep = 1;
  } else if (normalized <= 2) {
    niceStep = 2;
  } else if (normalized <= 5) {
    niceStep = 5;
  } else {
    niceStep = 10;
  }

  const step = Math.max(1, niceStep * magnitude);
  const ceiling = Math.max(step, Math.ceil(safeMax / step) * step);
  const ticks = [];

  for (let value = 0; value <= ceiling; value += step) {
    ticks.push(value);
  }

  if (ticks[ticks.length - 1] !== ceiling) {
    ticks.push(ceiling);
  }

  return ticks;
}

function easeOutCubic(progress) {
  return 1 - (1 - progress) ** 3;
}

function interpolateNumber(start, end, progress) {
  return start + (end - start) * progress;
}

function getDatasetTopic(datasetInsights, topic) {
  const value = datasetInsights?.topics?.[topic];
  return isPlainObject(value) ? value : null;
}

function getTopicTopFeatures(datasetInsights, topic) {
  const section = getDatasetTopic(datasetInsights, topic);

  if (!isPlainObject(section) || !Array.isArray(section.top_features)) {
    return [];
  }

  return section.top_features
    .filter(
      (item) =>
        item &&
        item.label &&
        typeof item.importance === "number"
    );
}

function DonutChart({ topic }) {
  const [activeSegment, setActiveSegment] = useState("");
  const [visibleTooltipSegment, setVisibleTooltipSegment] = useState(null);
  const [isTooltipActive, setIsTooltipActive] = useState(false);
  const distribution = topic?.distribution || { positive: 0, negative: 0, total: 0 };
  const distributionLabels = topic?.distribution_labels || {};
  const [animatedDistribution, setAnimatedDistribution] = useState(() => ({
    positive: Number(distribution.positive || 0),
    negative: Number(distribution.negative || 0),
    total: Number(distribution.total || 0),
  }));
  const distributionRef = useRef(animatedDistribution);

  useEffect(() => {
    const nextDistribution = {
      positive: Number(distribution.positive || 0),
      negative: Number(distribution.negative || 0),
      total: Number(distribution.total || 0),
    };
    const startDistribution = distributionRef.current;
    const duration = 480;
    let frameId = 0;
    let cancelled = false;

    function animate(timestamp, startTime = timestamp) {
      if (cancelled) {
        return;
      }

      const progress = Math.min((timestamp - startTime) / duration, 1);
      const eased = easeOutCubic(progress);
      const nextValue = {
        positive: interpolateNumber(startDistribution.positive, nextDistribution.positive, eased),
        negative: interpolateNumber(startDistribution.negative, nextDistribution.negative, eased),
        total: interpolateNumber(startDistribution.total, nextDistribution.total, eased),
      };

      distributionRef.current = nextValue;
      setAnimatedDistribution(nextValue);

      if (progress < 1) {
        frameId = window.requestAnimationFrame((nextTimestamp) => animate(nextTimestamp, startTime));
      }
    }

    frameId = window.requestAnimationFrame(animate);

    return () => {
      cancelled = true;
      window.cancelAnimationFrame(frameId);
    };
  }, [distribution.negative, distribution.positive, distribution.total]);

  const segments = [
    {
      label: distributionLabels.positive || "Positive",
      value: animatedDistribution.positive,
      className: "donut-chart__ring--warning",
      colorClass: "donut-chart__legend-dot--warning",
    },
    {
      label: distributionLabels.negative || "Negative",
      value: animatedDistribution.negative,
      className: "donut-chart__ring--safe",
      colorClass: "donut-chart__legend-dot--safe",
    },
  ].filter((segment) => segment.value > 0.001);

  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  const radius = 72;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const highlightedSegment = segments.find((segment) => segment.label === activeSegment) || null;

  useEffect(() => {
    let timeoutId = 0;

    if (highlightedSegment) {
      setVisibleTooltipSegment(highlightedSegment);
      setIsTooltipActive(true);
      return undefined;
    }

    setIsTooltipActive(false);
    timeoutId = window.setTimeout(() => {
      setVisibleTooltipSegment(null);
    }, 180);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [highlightedSegment]);

  return (
    <div className="donut-chart">
      <svg className="donut-chart__svg" viewBox="0 0 220 220" role="img">
        <circle className="donut-chart__track" cx="110" cy="110" r={radius} />
        {segments.map((segment) => {
          const dash = total ? (segment.value / total) * circumference : 0;
          const ring = (
            <circle
              key={segment.label}
              className={segment.className}
              cx="110"
              cy="110"
              r={radius}
              opacity={!activeSegment || activeSegment === segment.label ? 1 : 0.28}
              onBlur={() => setActiveSegment("")}
              onFocus={() => setActiveSegment(segment.label)}
              onMouseEnter={() => setActiveSegment(segment.label)}
              onMouseLeave={() => setActiveSegment("")}
              strokeDasharray={`${dash} ${circumference - dash}`}
              strokeDashoffset={-offset}
              style={{
                cursor: "pointer",
                strokeWidth: activeSegment === segment.label ? 24 : 20,
                transition: "opacity 0.2s ease, stroke-width 0.2s ease",
              }}
              tabIndex={0}
            />
          );
          offset += dash;
          return ring;
        })}
        <g className="donut-chart__center">
          <text x="110" y="102">Total</text>
          <text x="110" y="128">{Math.round(animatedDistribution.total || total)}</text>
        </g>
      </svg>

      <div className="donut-chart__legend">
        {segments.map((segment) => (
          <button
            className={`donut-chart__legend-item${
              activeSegment === segment.label ? " is-active" : ""
            }`}
            key={segment.label}
            onBlur={() => setActiveSegment("")}
            onFocus={() => setActiveSegment(segment.label)}
            onMouseEnter={() => setActiveSegment(segment.label)}
            onMouseLeave={() => setActiveSegment("")}
            type="button"
          >
            <span>
              <span className={`donut-chart__legend-dot ${segment.colorClass}`} />
              {segment.label}
            </span>
            <strong>{Math.round(segment.value)}</strong>
          </button>
        ))}
      </div>

      {visibleTooltipSegment ? (
        <div className={`chart-tooltip${isTooltipActive ? " is-active" : ""}`}>
          <strong>{visibleTooltipSegment.label}</strong>
          <span>{Math.round(visibleTooltipSegment.value)} records</span>
          <span>
            {total ? ((visibleTooltipSegment.value / total) * 100).toFixed(1) : "0.0"}% share
          </span>
        </div>
      ) : null}
    </div>
  );
}

function FeatureImportanceChart({ rows }) {
  const [hoveredBar, setHoveredBar] = useState(null);
  const [visibleTooltipBar, setVisibleTooltipBar] = useState(null);
  const [isTooltipActive, setIsTooltipActive] = useState(false);
  const width = 700;
  const height = Math.max(360, rows.length * 28 + 84);
  const padding = { top: 22, right: 24, bottom: 42, left: 168 };

  useEffect(() => {
    let timeoutId = 0;

    if (hoveredBar) {
      setVisibleTooltipBar(hoveredBar);
      setIsTooltipActive(true);
      return undefined;
    }

    setIsTooltipActive(false);
    timeoutId = window.setTimeout(() => {
      setVisibleTooltipBar(null);
    }, 180);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [hoveredBar]);

  if (!rows.length) {
    return (
      <div className="empty-card">
        <h3>No feature importance yet</h3>
        <p>Expose model feature importance values from the backend and this chart will populate.</p>
      </div>
    );
  }

  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const rowHeight = chartHeight / rows.length;
  const barHeight = Math.min(24, rowHeight * 0.62);
  const maxValue = Math.max(...rows.map((row) => row.importance), 1);
  const xTicks = [0, 25, 50, 75, 100];

  return (
    <div className="topic-chart">
      <svg className="topic-chart__svg" viewBox={`0 0 ${width} ${height}`} role="img">
        {xTicks.map((tick) => {
          const x = padding.left + (tick / 100) * chartWidth;
          return (
            <g key={`importance-tick-${tick}`}>
              <line
                stroke="rgba(191, 209, 228, 0.7)"
                strokeDasharray="5 7"
                x1={x}
                x2={x}
                y1={padding.top}
                y2={height - padding.bottom}
              />
              <text
                fill="#6b7f94"
                fontSize="12"
                fontWeight="700"
                textAnchor={tick === 100 ? "end" : tick === 0 ? "start" : "middle"}
                x={x}
                y={height - 16}
              >
                {tick}%
              </text>
            </g>
          );
        })}

        {rows.map((row, index) => {
          const barWidth = (row.importance / maxValue) * chartWidth;
          const y = padding.top + index * rowHeight + (rowHeight - barHeight) / 2;

          return (
            <g key={row.id}>
              <text
                fill="#6b7f94"
                fontSize="12"
                fontWeight="700"
                textAnchor="end"
                x={padding.left - 12}
                y={y + barHeight / 2 + 4}
              >
                {row.label}
              </text>
              <rect
                className="topic-chart__track"
                fill="rgba(15, 109, 255, 0.08)"
                height={barHeight}
                rx="7"
                width={chartWidth}
                x={padding.left}
                y={y}
              />
              <rect
                className={`topic-chart__bar${
                  hoveredBar?.id === row.id ? " is-active" : ""
                }`}
                fill="url(#featureImportanceFill)"
                height={barHeight}
                onMouseEnter={() =>
                  setHoveredBar({
                    id: row.id,
                    label: row.label,
                    value: row.importance,
                    rawValue: row.raw_importance,
                    x: padding.left + barWidth,
                    y,
                  })
                }
                onMouseLeave={() => setHoveredBar(null)}
                rx="7"
                width={Math.max(barWidth, 6)}
                x={padding.left}
                y={y}
              />
              <text
                fill="#16324c"
                fontSize="12"
                fontWeight="700"
                textAnchor="end"
                x={Math.min(width - padding.right - 8, padding.left + Math.max(barWidth, 6) + 42)}
                y={y + barHeight / 2 + 4}
              >
                {row.importance.toFixed(1)}%
              </text>
            </g>
          );
        })}

        <defs>
          <linearGradient id="featureImportanceFill" x1="0%" x2="100%" y1="0%" y2="0%">
            <stop offset="0%" stopColor="#2563eb" />
            <stop offset="100%" stopColor="#7dd3fc" />
          </linearGradient>
        </defs>

        {visibleTooltipBar ? (
          <g
            className={`chart-tooltip-group${isTooltipActive ? " is-active" : ""}`}
            pointerEvents="none"
          >
            <rect
              className="chart-tooltip__bubble"
              height="68"
              rx="14"
              width="164"
              x={Math.max(16, Math.min(width - 180, visibleTooltipBar.x - 82))}
              y={Math.max(16, visibleTooltipBar.y - 82)}
            />
            <text
              className="chart-tooltip__title"
              x={Math.max(28, Math.min(width - 168, visibleTooltipBar.x - 70))}
              y={Math.max(38, visibleTooltipBar.y - 58)}
            >
              {visibleTooltipBar.label}
            </text>
            <text
              className="chart-tooltip__meta"
              x={Math.max(28, Math.min(width - 168, visibleTooltipBar.x - 70))}
              y={Math.max(56, visibleTooltipBar.y - 40)}
            >
              Relative importance
            </text>
            <text
              className="chart-tooltip__value"
              x={Math.max(28, Math.min(width - 168, visibleTooltipBar.x - 70))}
              y={Math.max(76, visibleTooltipBar.y - 20)}
            >
              {visibleTooltipBar.value.toFixed(1)}% ({visibleTooltipBar.rawValue.toFixed(3)} raw)
            </text>
          </g>
        ) : null}
      </svg>
    </div>
  );
}

function TrendChart({ rows, meta }) {
  const [hoveredPointKey, setHoveredPointKey] = useState("");
  const [visibleTooltipPointKey, setVisibleTooltipPointKey] = useState("");
  const [isTooltipActive, setIsTooltipActive] = useState(false);
  const [animatedRows, setAnimatedRows] = useState(rows);
  const animatedRowsRef = useRef(rows);
  const width = 720;
  const height = 280;
  const padding = { top: 24, right: 24, bottom: 48, left: 44 };

  useEffect(() => {
    const targetRows = (rows || []).map((row) => ({
      ...row,
      total_scans: Number(row.total_scans || 0),
      threat_count: Number(row.threat_count || 0),
    }));

    if (!targetRows.length) {
      animatedRowsRef.current = [];
      setAnimatedRows([]);
      return;
    }

    const startMap = new Map(
      (animatedRowsRef.current || []).map((row) => [row.day, row])
    );
    const duration = 520;
    let frameId = 0;
    let cancelled = false;

    function animate(timestamp, startTime = timestamp) {
      if (cancelled) {
        return;
      }

      const progress = Math.min((timestamp - startTime) / duration, 1);
      const eased = easeOutCubic(progress);
      const nextRows = targetRows.map((row) => {
        const startRow = startMap.get(row.day);
        return {
          ...row,
          total_scans: interpolateNumber(
            Number(startRow?.total_scans || 0),
            row.total_scans,
            eased
          ),
          threat_count: interpolateNumber(
            Number(startRow?.threat_count || 0),
            row.threat_count,
            eased
          ),
        };
      });

      animatedRowsRef.current = nextRows;
      setAnimatedRows(nextRows);

      if (progress < 1) {
        frameId = window.requestAnimationFrame((nextTimestamp) => animate(nextTimestamp, startTime));
      }
    }

    frameId = window.requestAnimationFrame(animate);

    return () => {
      cancelled = true;
      window.cancelAnimationFrame(frameId);
    };
  }, [rows]);

  useEffect(() => {
    let timeoutId = 0;

    if (hoveredPointKey) {
      setVisibleTooltipPointKey(hoveredPointKey);
      setIsTooltipActive(true);
      return undefined;
    }

    setIsTooltipActive(false);
    timeoutId = window.setTimeout(() => {
      setVisibleTooltipPointKey("");
    }, 180);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [hoveredPointKey]);

  if (!animatedRows.length) {
    return null;
  }

  const maxValue = Math.max(
    ...animatedRows.flatMap((row) => [Number(row.total_scans || 0), Number(row.threat_count || 0)]),
    1
  );
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const stepX = animatedRows.length > 1 ? chartWidth / (animatedRows.length - 1) : 0;
  const barWidth =
    animatedRows.length > 14
      ? Math.max(10, stepX * 0.54)
      : Math.min(44, Math.max(stepX * 0.56, 18));

  const points = animatedRows.map((row, index) => {
    const totalScans = Number(row.total_scans || 0);
    const threatCount = Number(row.threat_count || 0);
    const x =
      animatedRows.length > 1
        ? padding.left + index * stepX
        : padding.left + chartWidth / 2;
    const barHeight = (totalScans / maxValue) * chartHeight;
    const lineY = padding.top + chartHeight - (threatCount / maxValue) * chartHeight;

    return {
      day: row.day,
      label: formatDateLabel(row.day),
      totalScans,
      threatCount,
      x,
      barX: x - barWidth / 2,
      barY: padding.top + chartHeight - barHeight,
      barHeight,
      lineY,
    };
  });
  const visibleTooltipPoint =
    points.find((point) => point.day === visibleTooltipPointKey) || null;

  const linePath = points
    .map((point, index) => `${index === 0 ? "M" : "L"} ${point.x.toFixed(2)} ${point.lineY.toFixed(2)}`)
    .join(" ");

  const yTickValues = Array.isArray(meta?.y_ticks) && meta.y_ticks.length
    ? meta.y_ticks
    : buildTrendTicks(maxValue);
  const displayMax = Math.max(yTickValues[yTickValues.length - 1] || 0, maxValue, 1);
  const yTicks = yTickValues.map((value) => {
    const ratio = value / displayMax;
    return {
      value,
      y: padding.top + chartHeight - ratio * chartHeight,
    };
  });
  const xTicks = buildTrendXAxisTicks(animatedRows);

  return (
    <div className="trend-chart">
      <div className="trend-chart__legend">
        <span className="trend-chart__legend-item">
          <span className="trend-chart__legend-swatch trend-chart__legend-swatch--bar" />
          Total scans
        </span>
        <span className="trend-chart__legend-item">
          <span className="trend-chart__legend-swatch trend-chart__legend-swatch--line" />
          Threats
        </span>
      </div>

      <svg className="trend-chart__svg" viewBox={`0 0 ${width} ${height}`} role="img">
        <defs>
          <linearGradient id="trendBarFill" x1="0%" x2="0%" y1="0%" y2="100%">
            <stop offset="0%" stopColor="#8bc0ff" />
            <stop offset="100%" stopColor="#2563eb" />
          </linearGradient>
        </defs>

        {yTicks.map((tick) => (
          <g key={`tick-${tick.value}`}>
            <line
              stroke="rgba(191, 209, 228, 0.7)"
              strokeDasharray="5 7"
              x1={padding.left}
              x2={width - padding.right}
              y1={tick.y}
              y2={tick.y}
            />
            <text
              fill="#6b7f94"
              fontSize="12"
              fontWeight="700"
              textAnchor="end"
              x={padding.left - 10}
              y={tick.y + 4}
            >
              {tick.value}
            </text>
          </g>
        ))}

        {points.map((point, index) => (
          <g key={`${point.label}-${index}`}>
            <rect
              className="trend-chart__bar"
              height={Math.max(point.barHeight, 3)}
              onMouseEnter={() => setHoveredPointKey(point.day)}
              onMouseLeave={() => setHoveredPointKey("")}
              rx="10"
              width={barWidth}
              x={point.barX}
              y={point.barY}
            />
            {xTicks[index]?.showLabel ? (
              <text
                className={`trend-chart__label${
                  animatedRows.length > 14 ? " trend-chart__label--dense" : ""
                }`}
                fill="#6b7f94"
                fontSize="12"
                fontWeight="700"
                textAnchor={xTicks[index].textAnchor}
                x={point.x}
                y={height - 16}
              >
                {xTicks[index].label}
              </text>
            ) : null}
          </g>
        ))}

        <path className="trend-chart__line" d={linePath} />

        {points.map((point) => (
          <g key={`${point.day}-line`}>
            <circle
              className="trend-chart__dot-hitbox"
              cx={point.x}
              cy={point.lineY}
              fill="transparent"
              onMouseEnter={() => setHoveredPointKey(point.day)}
              onMouseLeave={() => setHoveredPointKey("")}
              r="11"
            />
            <circle
              className="trend-chart__dot"
              cx={point.x}
              cy={point.lineY}
              r="5"
            />
          </g>
        ))}

        {visibleTooltipPoint ? (
          <g
            className={`chart-tooltip-group${isTooltipActive ? " is-active" : ""}`}
            pointerEvents="none"
          >
            <line
              className="trend-chart__crosshair"
              x1={visibleTooltipPoint.x}
              x2={visibleTooltipPoint.x}
              y1={padding.top}
              y2={height - padding.bottom}
            />
            <rect
              className="chart-tooltip__bubble"
              height="74"
              rx="14"
              width="176"
              x={Math.max(14, Math.min(width - 190, visibleTooltipPoint.x - 88))}
              y={Math.max(16, visibleTooltipPoint.lineY - 92)}
            />
            <text
              className="chart-tooltip__title"
              x={Math.max(28, Math.min(width - 176, visibleTooltipPoint.x - 74))}
              y={Math.max(40, visibleTooltipPoint.lineY - 66)}
            >
              {visibleTooltipPoint.label}
            </text>
            <text
              className="chart-tooltip__meta"
              x={Math.max(28, Math.min(width - 176, visibleTooltipPoint.x - 74))}
              y={Math.max(58, visibleTooltipPoint.lineY - 48)}
            >
              {Math.round(visibleTooltipPoint.totalScans)} total scans
            </text>
            <text
              className="chart-tooltip__value"
              x={Math.max(28, Math.min(width - 176, visibleTooltipPoint.x - 74))}
              y={Math.max(80, visibleTooltipPoint.lineY - 26)}
            >
              {Math.round(visibleTooltipPoint.threatCount)} threats
            </text>
          </g>
        ) : null}
      </svg>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState({});
  const [datasetInsights, setDatasetInsights] = useState({});
  const [dashboardLoading, setDashboardLoading] = useState(true);
  const [datasetLoading, setDatasetLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTopic, setActiveTopic] = useState("url");
  const [activeMapTopic, setActiveMapTopic] = useState("all");
  const [trendWindow, setTrendWindow] = useState("week");

  async function loadDashboardData(range = trendWindow) {
    setDashboardLoading(true);

    try {
      const statsResult = await getDashboard(range);
      setStats(statsResult || {});
      setError("");
    } catch (statsError) {
      setStats({});
      setError(
        getApiErrorMessage(
          statsError,
          "Dashboard statistics could not be loaded at the moment."
        )
      );
    } finally {
      setDashboardLoading(false);
    }
  }

  async function loadDatasetInsightsData() {
    setDatasetLoading(true);

    try {
      const datasetResult = await getDatasetInsights();
      setDatasetInsights(datasetResult || {});
    } catch (datasetError) {
      setDatasetInsights({});
      setError((current) =>
        [
          current,
          getApiErrorMessage(
            datasetError,
            "Dataset insights could not be loaded at the moment."
          ),
        ]
          .filter(Boolean)
          .join(" ")
      );
    } finally {
      setDatasetLoading(false);
    }
  }

  useEffect(() => {
    loadDashboardData(trendWindow);
  }, [trendWindow]);

  useEffect(() => {
    loadDatasetInsightsData();
  }, []);

  const loading = dashboardLoading || datasetLoading;

  const summary = getSummary(stats);
  const dataSource = stats?.data_source || "unknown";
  const typeCards = ["url", "file", "email"]
    .map((type) => ({
      type,
      entries: getReadableEntries(getTypeStats(stats, type)),
    }))
    .filter((item) => item.entries.length > 0);
  const trendRows = Array.isArray(stats?.trend) ? stats.trend : [];
  const trendMeta = stats?.trend_meta || {};
  const countryStats = Array.isArray(stats?.country_stats) ? stats.country_stats : [];
  const recentDetections = Array.isArray(stats?.recent_detections)
    ? stats.recent_detections
    : [];
  const activeDatasetTopic = getDatasetTopic(datasetInsights, activeTopic);
  const topicTopFeatures = getTopicTopFeatures(datasetInsights, activeTopic);
  const filteredCountries = countryStats
    .map((country) => {
      const typeBucket =
        activeMapTopic !== "all" ? country.by_type?.[activeMapTopic] || null : null;
      const totalScans =
        activeMapTopic === "all"
          ? Number(country.total_scans || 0)
          : Number(typeBucket?.total_scans || 0);
      const threatCount =
        activeMapTopic === "all"
          ? Number(country.threat_count || 0)
          : Number(typeBucket?.threat_count || 0);
      const threatRatio = totalScans ? (threatCount / totalScans) * 100 : 0;

      return {
        ...country,
        total_scans: totalScans,
        threat_count: threatCount,
        threat_ratio: threatRatio,
      };
    })
    .filter((country) => country.total_scans > 0)
    .sort((left, right) => right.total_scans - left.total_scans);
  const topCountries = filteredCountries.slice(0, 3);

  return (
    <div className="page-shell page">
      <PageHeader
        actions={
          <button
            className="btn btn--secondary"
            onClick={() => loadDashboardData(trendWindow)}
            type="button"
          >
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

      <section className="panel panel--subtle">
        <div className="page-header">
          <div className="page-header__content">
            <h2 className="panel__title">Live activity map</h2>
            <p className="panel__description">
              Color each country by threat rate, then filter the view by scan type.
            </p>
          </div>

          <div className="dashboard-toolbar">
            <div className="toggle-group toggle-group--topic">
              {MAP_TOPIC_OPTIONS.map((topic) => (
                <button
                  className={activeMapTopic === topic.id ? "is-active" : ""}
                  key={topic.id}
                  onClick={() => setActiveMapTopic(topic.id)}
                  type="button"
                >
                  {topic.label}
                </button>
              ))}
            </div>

          </div>
        </div>

        {filteredCountries.length ? (
          <>
            <div style={{ marginTop: "1rem" }}>
              <ThreatMap
                activeType={activeMapTopic}
                countryStats={countryStats}
              />
            </div>

            <div className="map-legend">
              <span className="map-legend__item">
                <span className="map-legend__dot map-legend__dot--danger" />
                High threat rate
              </span>
              <span className="map-legend__item">
                <span className="map-legend__dot map-legend__dot--warning" />
                Medium threat rate
              </span>
              <span className="map-legend__item">
                <span className="map-legend__dot map-legend__dot--safe" />
                Low threat rate
              </span>
              <span className="map-legend__hint">Hover a country to inspect scans, threats, and threat rate.</span>
            </div>
          </>
        ) : (
          <div className="empty-card" style={{ marginTop: "1rem" }}>
            <h3>No map activity yet</h3>
            <p>As soon as stored detections include country data, the threat-rate map will render here.</p>
          </div>
        )}
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

      <section className="dashboard-main-grid">
        <div className="dashboard-column">
          <article className="panel">
            <div className="page-header">
              <div className="page-header__content">
                <h2 className="panel__title">Detection trend</h2>
                <p className="panel__description">
                  Hover bars and dots to inspect daily volume and threat spikes.
                </p>
              </div>

              <div className="toggle-group toggle-group--compact">
                <button
                  className={trendWindow === "week" ? "is-active" : ""}
                  onClick={() => setTrendWindow("week")}
                  type="button"
                >
                  Week
                </button>
                <button
                  className={trendWindow === "month" ? "is-active" : ""}
                  onClick={() => setTrendWindow("month")}
                  type="button"
                >
                  Month
                </button>
              </div>
            </div>

            {trendRows.length ? (
              <div style={{ marginTop: "1rem" }}>
                <TrendChart meta={trendMeta} rows={trendRows} />
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
              <div className="country-list" style={{ marginTop: "1rem" }}>
                {topCountries.slice(0, 3).map((country, index) => {
                  const totalScans = Number(country.total_scans || 0);
                  const threatCount = Number(country.threat_count || 0);
                  const threatRatio = Number(country.threat_ratio || 0);

                  return (
                    <article
                      className="country-card"
                      key={`${country.country_code || "xx"}-${country.country_name || "unknown"}`}
                    >
                      <div className="country-card__header">
                        <span className="country-card__rank">#{index + 1}</span>
                        <span className="country-card__code">
                          {formatCountryCode(country.country_code)}
                        </span>
                      </div>
                      <div className="country-card__body">
                        <div>
                          <h3 className="country-card__title">
                            {country.country_name || "Unknown"}
                          </h3>
                          <p className="country-card__meta">
                            {totalScans} {activeMapTopic === "all" ? "scans tracked" : `${activeMapTopic} scans tracked`}
                          </p>
                        </div>
                        <div className="country-card__stats">
                          <strong>{threatCount}</strong>
                          <span>threats</span>
                        </div>
                      </div>
                      <div className="country-card__bar">
                        <span
                          className="country-card__bar-fill"
                          style={{
                            width: `${Math.max(threatRatio, 8)}%`,
                            background: `linear-gradient(90deg, ${getThreatRateColor(
                              Math.max(threatRatio - 18, 0)
                            )} 0%, ${getThreatRateColor(threatRatio)} 100%)`,
                          }}
                        />
                      </div>
                      <div className="country-card__footer">
                        <span>Threat share</span>
                        <strong>{threatRatio.toFixed(1)}%</strong>
                      </div>
                    </article>
                  );
                })}
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
        </div>

        <div className="dashboard-column">
          <article className="panel">
            <div className="page-header">
              <div className="page-header__content">
                <h2 className="panel__title">Detection mix</h2>
                <p className="panel__description">
                  Switch model topics and inspect how the training split changes.
                </p>
              </div>

              <div className="toggle-group toggle-group--topic">
                {TOPIC_OPTIONS.map((topic) => (
                  <button
                    className={activeTopic === topic.id ? "is-active" : ""}
                    key={topic.id}
                    onClick={() => setActiveTopic(topic.id)}
                    type="button"
                  >
                    {topic.label}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ marginTop: "1rem" }}>
              <DonutChart topic={activeDatasetTopic} />
            </div>
          </article>

          <article className="panel">
            <h2 className="panel__title">{formatLabel(activeTopic)} feature importance</h2>
            <p className="panel__description">
              Hover bars to inspect which signals matter most for the current model stack.
            </p>

            <div style={{ marginTop: "1rem" }}>
              <FeatureImportanceChart rows={topicTopFeatures} />
            </div>
          </article>
        </div>
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
    </div>
  );
}

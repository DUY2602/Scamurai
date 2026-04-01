function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function formatLabel(label) {
  return label
    .replace(/_/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatMetricValue(value, key = "") {
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

    if (Number.isInteger(value)) {
      return value.toLocaleString();
    }

    return value.toFixed(value >= 10 ? 1 : 4).replace(/\.?0+$/, "");
  }

  if (typeof value === "string") {
    return value.length > 280 ? `${value.slice(0, 280)}...` : value;
  }

  return String(value);
}

function polarToCartesian(cx, cy, radius, angleInDegrees) {
  const angleInRadians = (angleInDegrees * Math.PI) / 180.0;
  return {
    x: cx + radius * Math.cos(angleInRadians),
    y: cy - radius * Math.sin(angleInRadians),
  };
}

function describeArc(cx, cy, radius, startAngle, endAngle) {
  const start = polarToCartesian(cx, cy, radius, startAngle);
  const end = polarToCartesian(cx, cy, radius, endAngle);
  const largeArcFlag = Math.abs(endAngle - startAngle) <= 180 ? "0" : "1";
  const sweepFlag = startAngle > endAngle ? "1" : "0";

  return `M ${start.x} ${start.y} A ${radius} ${radius} 0 ${largeArcFlag} ${sweepFlag} ${end.x} ${end.y}`;
}

function describeSemiDisk(cx, cy, radius) {
  const left = polarToCartesian(cx, cy, radius, 180);
  const right = polarToCartesian(cx, cy, radius, 0);
  return `M ${left.x} ${left.y} A ${radius} ${radius} 0 0 1 ${right.x} ${right.y} L ${cx} ${cy} Z`;
}

function getTone(status, data) {
  const statusPool = [
    status,
    data?.verdict,
    data?.status,
    data?.classification,
    data?.label,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (
    /(malicious|malware|spam|phishing|danger|unsafe|threat|infected|fraud)/.test(
      statusPool
    )
  ) {
    return "danger";
  }

  if (/(suspicious|warning|review|unknown|caution)/.test(statusPool)) {
    return "warning";
  }

  if (/(benign|safe|clean|ham|trusted|legit)/.test(statusPool)) {
    return "safe";
  }

  if (typeof data?.is_malicious === "boolean") {
    return data.is_malicious ? "danger" : "safe";
  }

  if (typeof data?.is_spam === "boolean") {
    return data.is_spam ? "danger" : "safe";
  }

  return "neutral";
}

function getStatusText(status, data, tone) {
  const value =
    status ||
    data?.status ||
    data?.verdict ||
    data?.classification ||
    data?.label;

  if (value) {
    return formatLabel(String(value));
  }

  if (tone === "danger") {
    return "Threat Detected";
  }

  if (tone === "warning") {
    return "Needs Review";
  }

  if (tone === "safe") {
    return "Low Risk";
  }

  return "Analysis Ready";
}

function getGaugeMeta(tone) {
  if (tone === "danger") {
    return {
      caption: "Escalated risk profile",
    };
  }

  if (tone === "warning") {
    return {
      caption: "Borderline risk profile",
    };
  }

  if (tone === "safe") {
    return {
      caption: "Stable low-risk profile",
    };
  }

  return {
    caption: "Current scan profile",
  };
}

const PRIORITY_SCALAR_KEYS = [
  "confidence",
  "predicted_class",
  "model_agreement",
  "signal_strength",
];

function getToneMeta(tone) {
  if (tone === "danger") {
    return {
      descriptor: "High-priority threat signal",
    };
  }

  if (tone === "warning") {
    return {
      descriptor: "Suspicious activity needs review",
    };
  }

  if (tone === "safe") {
    return {
      descriptor: "Low-risk result from the latest scan",
    };
  }

  return {
    descriptor: "Latest analysis result from Scamurai",
  };
}

function shouldHideEntry(key, value) {
  if (value === null || value === undefined || value === "") {
    return true;
  }

  if (
    typeof value === "string" &&
    value.length > 1200 &&
    /(raw|body|html|content|text)/i.test(key)
  ) {
    return true;
  }

  if (Array.isArray(value) && value.length > 18 && !isPlainObject(value[0])) {
    return true;
  }

  return false;
}

function renderNode(key, value, depth = 0) {
  if (shouldHideEntry(key, value)) {
    return null;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return null;
    }

    const primitiveItems = value.every((item) => !isPlainObject(item));

    if (primitiveItems) {
      const previewItems = value.slice(0, 10);

      return (
        <div className="nested-block">
          <h4 className="nested-block__title">{formatLabel(key)}</h4>
          <div className="tag-list">
            {previewItems.map((item, index) => (
              <span className="tag" key={`${key}-${index}`}>
                {formatMetricValue(item, key)}
              </span>
            ))}
          </div>
          {value.length > previewItems.length ? (
            <p className="inline-muted">
              Showing {previewItems.length} of {value.length} items for readability.
            </p>
          ) : null}
        </div>
      );
    }

    return (
      <div className="nested-block">
        <h4 className="nested-block__title">{formatLabel(key)}</h4>
        <div className="grid">
          {value.slice(0, 3).map((item, index) => (
            <div key={`${key}-${index}`}>{renderNode(`Item ${index + 1}`, item, depth + 1)}</div>
          ))}
        </div>
        {value.length > 3 ? (
          <p className="inline-muted">Showing 3 of {value.length} nested entries.</p>
        ) : null}
      </div>
    );
  }

  if (isPlainObject(value)) {
    const entries = Object.entries(value).filter(
      ([childKey, childValue]) => !shouldHideEntry(childKey, childValue)
    );

    if (entries.length === 0) {
      return null;
    }

    return (
      <div className="nested-block">
        <h4 className="nested-block__title">{formatLabel(key)}</h4>
        <div className="kv-grid">
          {entries.map(([childKey, childValue]) => {
            if (Array.isArray(childValue) || isPlainObject(childValue)) {
              return (
                <div className="full-span" key={`${key}-${childKey}`}>
                  {renderNode(childKey, childValue, depth + 1)}
                </div>
              );
            }

            return (
              <div className="kv-item" key={`${key}-${childKey}`}>
                <span className="kv-item__label">{formatLabel(childKey)}</span>
                <p className="kv-item__value">
                  {formatMetricValue(childValue, childKey)}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  return (
    <div className={`kv-item${depth > 0 ? " full-span" : ""}`}>
      <span className="kv-item__label">{formatLabel(key)}</span>
      <p className="kv-item__value">{formatMetricValue(value, key)}</p>
    </div>
  );
}

export default function ResultCard({ title, status, score, data }) {
  if (!data) {
    return null;
  }

  const tone = getTone(status, data);
  const toneMeta = getToneMeta(tone);
  const gaugeMeta = getGaugeMeta(tone);
  const statusText = getStatusText(status, data, tone);
  const scoreValue = score ?? data?.risk_score;
  const numericScore = Number.isFinite(Number(scoreValue)) ? Math.max(0, Math.min(100, Number(scoreValue))) : null;
  const needleAngle = numericScore === null ? 180 : 180 - (numericScore * 180) / 100;
  const needlePoint = polarToCartesian(160, 160, 102, needleAngle);
  const gaugeSegments = [
    { color: "#2fb24a", start: 180, end: 144 },
    { color: "#7fe135", start: 144, end: 108 },
    { color: "#ffef14", start: 108, end: 72 },
    { color: "#ffae22", start: 72, end: 36 },
    { color: "#ff5a21", start: 36, end: 0 },
  ];

  const duplicateKeys = new Set(["status", "classification", "label"]);
  const hiddenKeys = new Set([
    "detection_type",
    "source_value",
    "url",
    "filename",
    "subject_preview",
  ]);

  if (status || data?.verdict) {
    duplicateKeys.add("verdict");
  }

  if (score !== undefined && score !== null) {
    duplicateKeys.add("risk_score");
    duplicateKeys.add("score");
  }

  const scalarEntries = [];
  const nestedEntries = [];

  Object.entries(data).forEach(([key, value]) => {
    if (duplicateKeys.has(key) || hiddenKeys.has(key) || shouldHideEntry(key, value)) {
      return;
    }

    if (Array.isArray(value) || isPlainObject(value)) {
      nestedEntries.push([key, value]);
      return;
    }

    scalarEntries.push([key, value]);
  });

  const priorityEntries = PRIORITY_SCALAR_KEYS.flatMap((key) => {
    const matchedEntry = scalarEntries.find(([entryKey]) => entryKey === key);
    return matchedEntry ? [matchedEntry] : [];
  });

  return (
    <section className={`result-card result-card--${tone}`}>
      <div className="result-card__header">
        <div className="result-card__hero">
          <p className="eyebrow">Result</p>
          <div className="result-card__headline">
            <h2>{statusText}</h2>
          </div>
          <h3>{title || "Prediction Details"}</h3>
          <p>{toneMeta.descriptor}</p>
        </div>
        {scoreValue !== undefined && scoreValue !== null ? (
          <div className="result-card__summary">
            <div className="result-card__gauge-wrap">
              <div className="result-gauge" aria-hidden="true">
                <svg
                  className="result-gauge__svg"
                  viewBox="0 0 320 190"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  {gaugeSegments.map((segment) => (
                    <path
                      key={`${segment.start}-${segment.end}`}
                      d={describeArc(160, 160, 120, segment.start, segment.end)}
                      fill="none"
                      stroke={segment.color}
                      strokeLinecap="butt"
                      strokeWidth="42"
                    />
                  ))}
                  <path
                    d={describeSemiDisk(160, 160, 76)}
                    fill="rgba(255,255,255,0.96)"
                  />
                  <line
                    stroke="#2b3440"
                    strokeLinecap="round"
                    strokeWidth="4"
                    x1="160"
                    x2={needlePoint.x}
                    y1="160"
                    y2={needlePoint.y}
                  />
                  <circle cx="160" cy="160" fill="#2b3440" r="13" />
                  <circle cx="160" cy="160" fill="none" r="21" stroke="rgba(255,255,255,0.78)" strokeWidth="8" />
                </svg>
              </div>
              <div className="result-card__score-readout">
                <span>Risk Score</span>
                <strong>{formatMetricValue(scoreValue, "risk_score")}</strong>
              </div>
              <p className="result-card__gauge-copy">{gaugeMeta.caption}</p>
            </div>
          </div>
        ) : null}
      </div>

      {priorityEntries.length ? (
        <div className="kv-grid">
          {priorityEntries.map(([key, value]) => (
            <div className="kv-item" key={key}>
              <span className="kv-item__label">{formatLabel(key)}</span>
              <p className="kv-item__value">{formatMetricValue(value, key)}</p>
            </div>
          ))}
        </div>
      ) : null}

      {nestedEntries.length ? (
        <div className="grid">
          {nestedEntries.map(([key, value]) => (
            <div key={key}>{renderNode(key, value)}</div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

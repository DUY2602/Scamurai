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
    data?.verdict ||
    data?.status ||
    data?.classification ||
    data?.label;

  if (value) {
    return formatLabel(String(value));
  }

  if (tone === "danger") {
    return "Danger detected";
  }

  if (tone === "warning") {
    return "Needs review";
  }

  if (tone === "safe") {
    return "Looks safe";
  }

  return "Analysis complete";
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
  const statusText = getStatusText(status, data, tone);

  const duplicateKeys = new Set(["status", "classification", "label"]);

  if (status || data?.verdict) {
    duplicateKeys.add("verdict");
  }

  if (score !== undefined && score !== null) {
    duplicateKeys.add("risk_score");
    duplicateKeys.add("spam_probability");
    duplicateKeys.add("score");
  }

  const scalarEntries = [];
  const nestedEntries = [];

  Object.entries(data).forEach(([key, value]) => {
    if (duplicateKeys.has(key) || shouldHideEntry(key, value)) {
      return;
    }

    if (Array.isArray(value) || isPlainObject(value)) {
      nestedEntries.push([key, value]);
      return;
    }

    scalarEntries.push([key, value]);
  });

  return (
    <section className={`result-card result-card--${tone}`}>
      <div className="result-card__header">
        <div>
          <p className="eyebrow">Result</p>
          <h3>{title || "Scan Result"}</h3>
          <p>Readable output for the latest Scamurai analysis.</p>
        </div>

        <div className="result-card__summary">
          <span className={`status-badge status-badge--${tone}`}>{statusText}</span>
          {score !== undefined && score !== null ? (
            <span className="score-badge">
              Score {formatMetricValue(score, "risk_score")}
            </span>
          ) : null}
        </div>
      </div>

      {scalarEntries.length ? (
        <div className="kv-grid">
          {scalarEntries.map(([key, value]) => (
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

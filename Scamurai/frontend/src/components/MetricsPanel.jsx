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
      "auc",
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

  return String(value);
}

function getSection(metrics, aliases) {
  for (const alias of aliases) {
    if (isPlainObject(metrics?.[alias])) {
      return metrics[alias];
    }
  }

  return null;
}

function getPrimitiveEntries(source) {
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

function getModelGroups(sectionData) {
  if (!isPlainObject(sectionData)) {
    return [];
  }

  const groups = Object.entries(sectionData)
    .filter(([, value]) => isPlainObject(value) && getPrimitiveEntries(value).length)
    .map(([key, value]) => ({
      label: formatLabel(key),
      values: getPrimitiveEntries(value),
    }));

  if (groups.length > 0) {
    return groups;
  }

  const directValues = getPrimitiveEntries(sectionData);

  if (directValues.length > 0) {
    return [{ label: "Overview", values: directValues }];
  }

  return [];
}

const sections = [
  {
    id: "url",
    title: "URL Models",
    description: "Performance metrics for URL classification models.",
    aliases: ["url", "url_metrics", "urls"],
  },
  {
    id: "file",
    title: "File Models",
    description: "Metrics for malware or suspicious file detection.",
    aliases: ["file", "file_metrics", "files"],
  },
  {
    id: "email",
    title: "Email Models",
    description: "Metrics for spam and phishing email classifiers.",
    aliases: ["email", "email_metrics", "emails"],
  },
];

export default function MetricsPanel({ metrics }) {
  const availableSections = sections
    .map((section) => ({
      ...section,
      data: getSection(metrics, section.aliases),
    }))
    .filter((section) => isPlainObject(section.data));

  const fallbackGroups =
    availableSections.length === 0 && isPlainObject(metrics)
      ? getModelGroups(metrics)
      : [];

  if (!availableSections.length && !fallbackGroups.length) {
    return (
      <div className="empty-card">
        <h3>No model metrics yet</h3>
        <p>
          The dashboard will show model quality data here once the backend exposes
          metrics from URL, file, or email models.
        </p>
      </div>
    );
  }

  return (
    <section className="metrics-panel">
      {availableSections.map((section) => {
        const groups = getModelGroups(section.data);

        return (
          <div className="metrics-section" key={section.id}>
            <div className="metrics-section__header">
              <h3>{section.title}</h3>
              <p>{section.description}</p>
            </div>

            {groups.length ? (
              <div className="metrics-grid">
                {groups.map((group) => (
                  <article className="metric-card" key={`${section.id}-${group.label}`}>
                    <h4>{group.label}</h4>
                    <div className="metric-list">
                      {group.values.map(([key, value]) => (
                        <div className="metric-row" key={`${section.id}-${group.label}-${key}`}>
                          <span className="metric-row__label">{formatLabel(key)}</span>
                          <span className="metric-row__value">
                            {formatMetricValue(value, key)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <div className="empty-card">
                <h3>Metrics unavailable</h3>
                <p>No readable values were found for this section yet.</p>
              </div>
            )}
          </div>
        );
      })}

      {!availableSections.length && fallbackGroups.length ? (
        <div className="metrics-section">
          <div className="metrics-section__header">
            <h3>Model Overview</h3>
            <p>Generic metrics returned by the backend.</p>
          </div>
          <div className="metrics-grid">
            {fallbackGroups.map((group) => (
              <article className="metric-card" key={group.label}>
                <h4>{group.label}</h4>
                <div className="metric-list">
                  {group.values.map(([key, value]) => (
                    <div className="metric-row" key={`${group.label}-${key}`}>
                      <span className="metric-row__label">{formatLabel(key)}</span>
                      <span className="metric-row__value">
                        {formatMetricValue(value, key)}
                      </span>
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}

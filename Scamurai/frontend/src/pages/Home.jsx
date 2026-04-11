import { Link } from "react-router-dom";

const primaryActions = [
  {
    title: "URL Scan",
    badge: "URL",
    description: "Analyze risky links for phishing signals and domain abuse.",
    to: "/url",
  },
  {
    title: "File Scan",
    badge: "FILE",
    description: "Inspect executables for malware indicators and suspicious behavior.",
    to: "/file",
  },
  {
    title: "Email Scan",
    badge: "EMAIL",
    description: "Review spam and phishing signals from raw email content or .eml files.",
    to: "/email",
  },
];

const compactSignals = [
  {
    label: "Coverage",
    value: "3 surfaces",
    text: "URL, file, and email detection in one flow.",
  },
  {
    label: "Strength",
    value: "Clear verdicts",
    text: "Readable results for demos, reviews, and quick decisions.",
  },
  {
    label: "Visibility",
    value: "Live dashboard",
    text: "Open trends, hotspots, and recent detections from one place.",
  },
];

export default function Home() {
  return (
    <div className="page-shell page">
      <section className="landing-hero">
        <div className="hero-story hero-story--full panel panel--subtle">
          <div className="hero-story__topline">
            <p className="eyebrow">Cybersecurity Project</p>
            <span className="status-pill">Scamurai</span>
          </div>

          <h1 className="page-title hero-story__title hero-story__title--wide">
            Detect risky links, files, and emails from one clean security workspace.
          </h1>
          <p className="page-description hero-story__description hero-story__description--wide">
            Scamurai keeps the flow simple: run a scan, read the verdict fast, then move into the
            dashboard for trends and activity.
          </p>

          <div className="hero-cta-row">
            <Link className="btn btn--primary" to="/url">
              Start scanning
            </Link>
            <Link className="btn btn--secondary" to="/dashboard">
              Open dashboard
            </Link>
          </div>

          <div className="chip-row">
            <span className="chip chip--danger">Threat scoring</span>
            <span className="chip chip--warning">Dashboard insights</span>
            <span className="chip chip--safe">Readable output</span>
          </div>
        </div>
      </section>

      <section className="home-actions panel panel--subtle">
        <div className="home-actions__header">
          <div>
            <p className="eyebrow">Quick Actions</p>
            <h2 className="panel__title">Choose a scan path</h2>
          </div>
          <Link className="home-actions__dashboard-link" to="/dashboard">
            View full dashboard
          </Link>
        </div>

        <div className="home-actions__grid">
          {primaryActions.map((card) => (
            <Link className="action-card action-card--compact" key={card.to} to={card.to}>
              <span className="action-card__badge">{card.badge}</span>
              <h3 className="action-card__title">{card.title}</h3>
              <p className="action-card__description">{card.description}</p>
            </Link>
          ))}
        </div>
      </section>

      <section className="home-summary-strip">
        {compactSignals.map((item) => (
          <article className="home-summary-strip__item" key={item.label}>
            <span className="home-summary-strip__label">{item.label}</span>
            <strong className="home-summary-strip__value">{item.value}</strong>
            <p className="home-summary-strip__text">{item.text}</p>
          </article>
        ))}
      </section>
    </div>
  );
}

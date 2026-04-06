import { Link } from "react-router-dom";

const actionCards = [
  {
    title: "URL Scan",
    badge: "URL",
    description:
      "Analyze risky links for phishing signals, malicious patterns, and domain abuse.",
    to: "/url",
  },
  {
    title: "File Scan",
    badge: "FILE",
    description:
      "Inspect malware indicators, suspicious imports, and executable behavior flags.",
    to: "/file",
  },
  {
    title: "Email Scan",
    badge: "EMAIL",
    description:
      "Review spam, phishing, and social engineering signals from raw email content.",
    to: "/email",
  },
  {
    title: "Dashboard",
    badge: "STATS",
    description:
      "Track detections, hotspots, trends, and model health in one security dashboard.",
    to: "/dashboard",
  },
];

const highlights = [
  {
    title: "Malicious URLs",
    text: "Detect dangerous links before users click them.",
  },
  {
    title: "Suspicious Files",
    text: "Review malware-like traits from uploaded executables.",
  },
  {
    title: "Spam And Phishing Emails",
    text: "Screen raw email text or .eml attachments quickly.",
  },
];

const capabilityRows = [
  {
    step: "01",
    title: "Detect across attack surfaces",
    text: "Scan URLs, files, and emails from one unified security workflow.",
  },
  {
    step: "02",
    title: "Read risk fast",
    text: "Verdicts, scores, and supporting signals stay clear and presentation-ready.",
  },
  {
    step: "03",
    title: "Monitor live activity",
    text: "Move into the dashboard for hotspots, trends, and model monitoring.",
  },
];

export default function Home() {
  return (
    <div className="page-shell page">
      <section className="landing-hero">
        <div className="hero-story hero-story--full panel panel--subtle">
          <div className="hero-story__topline">
            <p className="eyebrow">Cybersecurity Project</p>
            <span className="status-pill">Landing page</span>
          </div>

          <h1 className="page-title hero-story__title hero-story__title--wide">
            Cybersecurity intelligence for links, files, and email threats.
          </h1>
          <p className="page-description hero-story__description hero-story__description--wide">
            Scamurai is built to surface digital threats fast, explain risk clearly, and turn
            complex detection output into a strong cyber defense story.
          </p>

          <div className="hero-cta-row">
            <Link className="btn btn--primary" to="/dashboard">
              Open dashboard
            </Link>
            <Link className="btn btn--secondary" to="/url">
              Start a quick scan
            </Link>
          </div>

          <div className="chip-row">
            <span className="chip chip--danger">Threat scoring</span>
            <span className="chip chip--warning">Analytics dashboard</span>
            <span className="chip chip--safe">Readable ML output</span>
            <span className="chip">Responsive UI</span>
          </div>

          <div className="hero-signal-grid">
            <article className="signal-card signal-card--primary">
              <span className="signal-card__label">Mission</span>
              <strong className="signal-card__value">Detect</strong>
              <p className="signal-card__meta">Expose malicious content across the most common cyber entry points.</p>
            </article>
            <article className="signal-card signal-card--danger">
              <span className="signal-card__label">Value</span>
              <strong className="signal-card__value">Explain</strong>
              <p className="signal-card__meta">Translate model output into clear risk signals for users and reviewers.</p>
            </article>
            <article className="signal-card signal-card--dark">
              <span className="signal-card__label">Ops View</span>
              <strong className="signal-card__value">Monitor</strong>
              <p className="signal-card__meta">Follow live detections, hotspot movement, and model health from one place.</p>
            </article>
          </div>
        </div>

        <div className="landing-band">
          <div className="landing-band__intro">
            <p className="eyebrow">How It Flows</p>
            <h2 className="landing-band__title">Introduce, detect, monitor</h2>
          </div>
          <div className="landing-band__grid">
            {capabilityRows.map((item) => (
              <article className="timeline-card" key={item.step}>
                <span className="timeline-card__step">{item.step}</span>
                <h3 className="timeline-card__title">{item.title}</h3>
                <p className="timeline-card__text">{item.text}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section>
        <div className="page-header">
          <div className="page-header__content">
            <p className="eyebrow">Quick Actions</p>
            <h2 className="page-title" style={{ fontSize: "2rem" }}>
              Start scanning now
            </h2>
            <p className="page-description">
              Launch a scan instantly or jump into the dashboard for live security analytics.
            </p>
          </div>
        </div>

        <div className="grid grid--four" style={{ marginTop: "1rem" }}>
          {actionCards.map((card) => (
            <Link className="action-card action-card--spotlight" key={card.to} to={card.to}>
              <span className="action-card__badge">{card.badge}</span>
              <h3 className="action-card__title">{card.title}</h3>
              <p className="action-card__description">{card.description}</p>
              <div className="action-card__meta">Open page</div>
            </Link>
          ))}
        </div>
      </section>

      <section className="overview-strip">
        <article className="overview-strip__card">
          <p className="overview-strip__label">Coverage</p>
          <h3 className="overview-strip__title">Three threat surfaces</h3>
          <p className="overview-strip__text">Protect against malicious links, suspicious files, and phishing email content.</p>
        </article>
        <article className="overview-strip__card">
          <p className="overview-strip__label">Positioning</p>
          <h3 className="overview-strip__title">Built for cybersecurity demos</h3>
          <p className="overview-strip__text">Clean enough for presentation, technical enough to show real detection logic.</p>
        </article>
        <article className="overview-strip__card">
          <p className="overview-strip__label">Outcome</p>
          <h3 className="overview-strip__title">Fast risk communication</h3>
          <p className="overview-strip__text">Surface the verdict fast, then back it up with metrics and live monitoring.</p>
        </article>
      </section>

      <section className="panel">
        <div className="page-header">
          <div className="page-header__content">
            <p className="eyebrow">Project Focus</p>
            <h2 className="panel__title">Built to communicate cyber risk fast</h2>
            <p className="panel__description">
              Scamurai turns raw detection signals into readable cybersecurity insight for demos,
              reviews, and fast decision-making.
            </p>
          </div>
        </div>

        <div className="trust-banner">
          <div>
            <span className="trust-banner__label">Outcome</span>
            <strong className="trust-banner__title">A sharper cyber defense story from input to verdict</strong>
          </div>
          <p className="trust-banner__text">
            Introduce the platform here, run detection flows in the scan pages, then move into the
            dashboard to show live activity and model awareness.
          </p>
        </div>

        <h2 className="panel__title">Project purpose</h2>
        <p className="panel__description">
          Scamurai demonstrates how machine learning can help identify and explain digital threats
          across core cybersecurity vectors.
        </p>

        <div className="grid grid--three" style={{ marginTop: "1rem" }}>
          {highlights.map((highlight) => (
            <article className="action-card action-card--spotlight" key={highlight.title}>
              <span className="action-card__badge">Focus</span>
              <h3 className="action-card__title">{highlight.title}</h3>
              <p className="action-card__description">{highlight.text}</p>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getApiErrorMessage, getDashboard } from "../api/scamurai_api";
import ThreatMap from "../components/ThreatMap";

const actionCards = [
  {
    title: "URL Scan",
    badge: "URL",
    description:
      "Check suspicious links for malicious patterns, phishing signals, and risky domains.",
    to: "/url",
  },
  {
    title: "File Scan",
    badge: "FILE",
    description:
      "Upload one file to inspect malware signals, risky imports, and suspicious PE features.",
    to: "/file",
  },
  {
    title: "Email Scan",
    badge: "EMAIL",
    description:
      "Paste email content or upload an .eml file to review spam and phishing probability.",
    to: "/email",
  },
  {
    title: "Dashboard",
    badge: "STATS",
    description:
      "Monitor overall scan counts, suspicious activity, and available model metrics in one view.",
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
    title: "Spam & Phishing Emails",
    text: "Screen raw email text or .eml attachments quickly.",
  },
];

export default function Home() {
  const [mapPoints, setMapPoints] = useState([]);
  const [mapError, setMapError] = useState("");

  useEffect(() => {
    let active = true;

    getDashboard()
      .then((data) => {
        if (!active) {
          return;
        }

        setMapPoints(Array.isArray(data?.map_points) ? data.map_points : []);
        setMapError("");
      })
      .catch((error) => {
        if (!active) {
          return;
        }

        setMapPoints([]);
        setMapError(
          getApiErrorMessage(error, "Could not load live world map activity.")
        );
      });

    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="page-shell page">
      <section className="hero-panel">
        <div className="panel panel--subtle">
          <p className="eyebrow">Cybersecurity Project</p>
          <h1 className="page-title">
            Scamurai helps you scan common scam signals in one clean dashboard.
          </h1>
          <p className="page-description">
            Built as a polished student project, Scamurai brings together URL
            analysis, file inspection, and email screening with simple, readable
            results that are easy to demo and easy to understand.
          </p>

          <div className="chip-row">
            <span className="chip chip--danger">Danger states in red</span>
            <span className="chip chip--warning">Warnings in amber</span>
            <span className="chip chip--safe">Safe states in green</span>
            <span className="chip">Responsive interface</span>
          </div>
        </div>

        <div className="hero-stats">
          <div className="hero-stat">
            <strong>3 scan types</strong>
            <p>URL, file, and email analysis in a single workflow.</p>
          </div>
          <div className="hero-stat">
            <strong>Readable results</strong>
            <p>Structured cards instead of raw JSON dumps.</p>
          </div>
          <div className="hero-stat">
            <strong>Dashboard ready</strong>
            <p>Gracefully handles empty stats while your backend grows.</p>
          </div>
        </div>
      </section>

      <section>
        <div className="page-header">
          <div className="page-header__content">
            <p className="eyebrow">Quick Actions</p>
            <h2 className="page-title" style={{ fontSize: "2rem" }}>
              Start a scan or open the dashboard
            </h2>
            <p className="page-description">
              Pick a workflow below to test the Scamurai interface and connect it
              to your backend models.
            </p>
          </div>
        </div>

        <div className="grid grid--four" style={{ marginTop: "1rem" }}>
          {actionCards.map((card) => (
            <Link className="action-card" key={card.to} to={card.to}>
              <span className="action-card__badge">{card.badge}</span>
              <h3 className="action-card__title">{card.title}</h3>
              <p className="action-card__description">{card.description}</p>
              <div className="action-card__meta">Open page</div>
            </Link>
          ))}
        </div>
      </section>

      <section className="panel panel--subtle">
        <div className="page-header">
          <div className="page-header__content">
            <p className="eyebrow">Live Activity Map</p>
            <h2 className="page-title" style={{ fontSize: "2rem" }}>
              Global detection activity from live user scans
            </h2>
            <p className="page-description">
              Each point represents stored detections geolocated from request IPs.
              Larger dots mean more scans from the same location.
            </p>
          </div>
        </div>

        {mapError ? (
          <div className="feedback feedback--error" style={{ marginTop: "1rem" }}>
            {mapError}
          </div>
        ) : null}

        <div style={{ marginTop: "1rem" }}>
          <ThreatMap points={mapPoints} />
        </div>

        <div className="chip-row">
          <span className="chip chip--danger">Threat</span>
          <span className="chip chip--warning">Suspicious</span>
          <span className="chip">Safe / Other</span>
        </div>
      </section>

      <section className="panel">
        <h2 className="panel__title">Project purpose</h2>
        <p className="panel__description">
          Scamurai is designed to demonstrate how machine learning models can help
          identify risky digital content across several common cyber threat
          surfaces.
        </p>

        <div className="grid grid--three" style={{ marginTop: "1rem" }}>
          {highlights.map((highlight) => (
            <article className="action-card" key={highlight.title}>
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

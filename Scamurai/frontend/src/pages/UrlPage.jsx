import { useState } from "react";
import { analyzeUrl, getApiErrorMessage } from "../api/scamurai_api";
import PageHeader from "../components/PageHeader";
import ResultCard from "../components/ResultCard";

export default function UrlPage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  async function handleSubmit(event) {
    event.preventDefault();

    if (!url.trim()) {
      setError("Please enter a URL to analyze.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const data = await analyzeUrl(url.trim());
      setResult(data);
    } catch (requestError) {
      setError(
        getApiErrorMessage(
          requestError,
          "The URL scan failed. Please check the backend and try again."
        )
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page-shell page">
      <PageHeader
        eyebrow="URL Scanner"
        title="Inspect a link before you trust it"
        description="Paste a website URL to check verdict, risk score, and any suspicious indicators returned by the backend."
      />

      <div className="grid grid--scan">
        <section className="panel">
          <form className="form-grid" onSubmit={handleSubmit}>
            <label className="field" htmlFor="url-input">
              <span className="field__label">Website URL</span>
              <input
                id="url-input"
                className="field__input"
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com/login"
                type="url"
                value={url}
              />
            </label>

            <p className="helper-text">
              Full URLs work best, but Scamurai can also handle a plain domain in
              most cases.
            </p>

            {error ? <div className="feedback feedback--error">{error}</div> : null}

            <div className="btn-row">
              <button className="btn btn--primary" disabled={loading} type="submit">
                {loading ? "Scanning URL..." : "Analyze URL"}
              </button>
              <button
                className="btn btn--secondary"
                disabled={loading}
                onClick={() => {
                  setUrl("");
                  setError("");
                  setResult(null);
                }}
                type="button"
              >
                Clear
              </button>
            </div>
          </form>
        </section>

        <aside className="panel panel--subtle">
          <h2 className="panel__title">What this scan can show</h2>
          <ul className="feature-list">
            <li>
              <strong>Verdict and risk score</strong>
              High-level status for quick triage in demos and reports.
            </li>
            <li>
              <strong>Malicious flag</strong>
              Boolean output that is easy to map to safe or danger UI states.
            </li>
            <li>
              <strong>Supporting fields</strong>
              Any extra features, probabilities, or nested details are rendered in
              readable sections.
            </li>
          </ul>
        </aside>
      </div>

      {result ? (
        <ResultCard
          data={result}
          score={result.risk_score ?? result.score ?? result.avg_prob}
          status={result.verdict}
          title="URL Scan Result"
        />
      ) : (
        <div className="empty-card">
          <h3>No URL result yet</h3>
          <p>
            Submit a URL and Scamurai will display verdict, risk score, and any
            extra fields returned by the backend.
          </p>
        </div>
      )}
    </div>
  );
}

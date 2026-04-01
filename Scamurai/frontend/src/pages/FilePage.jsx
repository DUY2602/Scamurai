import { useEffect, useRef, useState } from "react";
import { analyzeFile, getApiErrorMessage } from "../api/scamurai_api";
import PageHeader from "../components/PageHeader";
import ResultCard from "../components/ResultCard";

export default function FilePage() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const resultRef = useRef(null);

  useEffect(() => {
    if (!result || !resultRef.current) {
      return;
    }

    resultRef.current.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  }, [result]);

  async function handleSubmit(event) {
    event.preventDefault();

    if (!selectedFile) {
      setError("Please choose a file to analyze.");
      return;
    }

    setLoading(true);
    setError("");

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const data = await analyzeFile(formData);
      setResult(data);
    } catch (requestError) {
      setError(
        getApiErrorMessage(
          requestError,
          "The file scan failed. Please try another file or check the backend."
        )
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page-shell page">
      <PageHeader
        eyebrow="File Scanner"
        title="Upload one file for a quick risk review"
        description="Use Scamurai to send a file to the backend and display malware verdicts, scores, and extracted feature details."
      />

      <div className="grid grid--scan">
        <section className="panel">
          <form className="form-grid" onSubmit={handleSubmit}>
            <label className="field" htmlFor="file-input">
              <span className="field__label">Choose a file</span>
              <input
                className="field__file"
                id="file-input"
                onChange={(event) => {
                  const file = event.target.files?.[0] || null;
                  setSelectedFile(file);
                }}
                type="file"
              />
            </label>

            <p className="helper-text">
              Scamurai currently supports single-file uploads through the backend
              analysis endpoint.
            </p>

            {selectedFile ? (
              <p className="file-name">Selected file: {selectedFile.name}</p>
            ) : null}

            {error ? <div className="feedback feedback--error">{error}</div> : null}

            <div className="btn-row">
              <button className="btn btn--primary" disabled={loading} type="submit">
                {loading ? "Scanning File..." : "Analyze File"}
              </button>
              <button
                className="btn btn--secondary"
                disabled={loading}
                onClick={() => {
                  setSelectedFile(null);
                  setError("");
                  setResult(null);
                }}
                type="button"
              >
                Reset
              </button>
            </div>

          </form>
        </section>

        <aside className="panel panel--subtle">
          <h2 className="panel__title">Expected output</h2>
          <ul className="feature-list">
            <li>
              <strong>Malware verdict</strong>
              Quickly show whether the backend classifies the file as benign or malware.
            </li>
            <li>
              <strong>Risk score</strong>
              Surface an easy-to-read threat level for presentations.
            </li>
            <li>
              <strong>Feature breakdown</strong>
              Nested PE or imported feature details appear in a structured card when available.
            </li>
          </ul>
        </aside>
      </div>

      {result ? (
        <div className="result-section" ref={resultRef}>
          <ResultCard
            data={result}
            score={result.risk_score ?? result.score}
            status={result.status ?? result.verdict}
            title="File Scan Result"
          />
        </div>
      ) : (
        <div className="empty-card">
          <h3>No file result yet</h3>
          <p>
            Choose one file and run the scan to see the backend verdict and
            supporting analysis output here.
          </p>
        </div>
      )}
    </div>
  );
}

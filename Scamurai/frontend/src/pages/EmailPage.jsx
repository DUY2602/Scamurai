import { useEffect, useRef, useState } from "react";
import {
  analyzeEmailFile,
  analyzeEmailText,
  getApiErrorMessage,
} from "../api/scamurai_api";
import PageHeader from "../components/PageHeader";
import ResultCard from "../components/ResultCard";

export default function EmailPage() {
  const [mode, setMode] = useState("text");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [emailFile, setEmailFile] = useState(null);
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

  async function handleTextSubmit(event) {
    event.preventDefault();

    if (!subject.trim() && !body.trim()) {
      setError("Please provide a subject or body before scanning.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const data = await analyzeEmailText(subject.trim(), body.trim());
      setResult(data);
    } catch (requestError) {
      setError(
        getApiErrorMessage(
          requestError,
          "The email text scan could not be completed. Please review the content and try again."
        )
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleFileSubmit(event) {
    event.preventDefault();

    if (!emailFile) {
      setError("Please choose an .eml file to analyze.");
      return;
    }

    setLoading(true);
    setError("");

    const formData = new FormData();
    formData.append("file", emailFile);

    try {
      const data = await analyzeEmailFile(formData);
      setResult(data);
    } catch (requestError) {
      setError(
        getApiErrorMessage(
          requestError,
          "The email file scan could not be completed. Please try a valid .eml file and run the scan again."
        )
      );
    } finally {
      setLoading(false);
    }
  }

  function resetInputs() {
    setSubject("");
    setBody("");
    setEmailFile(null);
    setError("");
    setResult(null);
  }

  return (
    <div className="page-shell page">
      <PageHeader
        eyebrow="Email Scanner"
        title="Review suspicious email content in two ways"
        description="Paste raw email text or upload an .eml file to inspect spam and phishing probability with a simple, readable result card."
      />

      <div aria-label="Email scan mode" className="toggle-group" role="tablist">
        <button
          className={mode === "text" ? "is-active" : ""}
          onClick={() => {
            setMode("text");
            setError("");
          }}
          role="tab"
          type="button"
        >
          Paste Email Text
        </button>
        <button
          className={mode === "file" ? "is-active" : ""}
          onClick={() => {
            setMode("file");
            setError("");
          }}
          role="tab"
          type="button"
        >
          Upload .eml File
        </button>
      </div>

      <div className="grid grid--scan">
        <section className="panel">
          {mode === "text" ? (
            <form className="form-grid" onSubmit={handleTextSubmit}>
              <label className="field" htmlFor="email-subject">
                <span className="field__label">Email subject</span>
                <input
                  className="field__input"
                  id="email-subject"
                  onChange={(event) => setSubject(event.target.value)}
                  placeholder="Urgent account verification required"
                  type="text"
                  value={subject}
                />
              </label>

              <label className="field" htmlFor="email-body">
                <span className="field__label">Email body</span>
                <textarea
                  className="field__textarea"
                  id="email-body"
                  onChange={(event) => setBody(event.target.value)}
                  placeholder="Paste the raw email content here..."
                  value={body}
                />
              </label>

              {error ? <div className="feedback feedback--error">{error}</div> : null}

              <div className="btn-row">
                <button className="btn btn--primary" disabled={loading} type="submit">
                  {loading ? "Scanning Email..." : "Analyze Email Text"}
                </button>
                <button
                  className="btn btn--secondary"
                  disabled={loading}
                  onClick={resetInputs}
                  type="button"
                >
                  Clear
                </button>
              </div>

            </form>
          ) : (
            <form className="form-grid" onSubmit={handleFileSubmit}>
              <label className="field" htmlFor="email-file">
                <span className="field__label">Upload .eml file</span>
                <input
                  accept=".eml,message/rfc822"
                  className="field__file"
                  id="email-file"
                  onChange={(event) => {
                    const file = event.target.files?.[0] || null;
                    setEmailFile(file);
                  }}
                  type="file"
                />
              </label>

              <p className="helper-text">
                Use this mode if you want Scamurai to parse a saved email file
                before sending it to the backend.
              </p>

              {emailFile ? (
                <p className="file-name">Selected file: {emailFile.name}</p>
              ) : null}

              {error ? <div className="feedback feedback--error">{error}</div> : null}

              <div className="btn-row">
                <button className="btn btn--primary" disabled={loading} type="submit">
                  {loading ? "Scanning Email..." : "Analyze Email File"}
                </button>
                <button
                  className="btn btn--secondary"
                  disabled={loading}
                  onClick={resetInputs}
                  type="button"
                >
                  Clear
                </button>
              </div>

            </form>
          )}
        </section>

        <aside className="panel panel--subtle">
          <h2 className="panel__title">Helpful notes</h2>
          <ul className="feature-list">
            <li>
              <strong>Text mode</strong>
              Best when you want to paste a suspicious subject line and message body quickly.
            </li>
            <li>
              <strong>File mode</strong>
              Useful for demoing how Scamurai handles uploaded .eml data from a mailbox export.
            </li>
            <li>
              <strong>Readable output</strong>
              Scamurai highlights spam probability, verdict, and other backend details without overwhelming the page.
            </li>
          </ul>
        </aside>
      </div>

      {result ? (
        <div className="result-section" ref={resultRef}>
          <ResultCard
            data={result}
            score={result.risk_score ?? result.spam_probability ?? result.score}
            status={result.status ?? result.verdict}
            title="Email Scan Result"
          />
        </div>
      ) : (
        <div className="empty-card">
          <h3>No email result yet</h3>
          <p>
            Use either text mode or file mode to send an email sample to the backend.
          </p>
        </div>
      )}
    </div>
  );
}

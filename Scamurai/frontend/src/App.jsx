import { Route, Routes, useLocation } from "react-router-dom";
import Navbar from "./components/Navbar";
import Home from "./pages/Home";
import UrlPage from "./pages/UrlPage";
import EmailPage from "./pages/EmailPage";
import FilePage from "./pages/FilePage";
import Dashboard from "./pages/Dashboard";

const apiBaseUrl =
  import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

export default function App() {
  const location = useLocation();

  return (
    <div className="app-shell">
      <Navbar />
      <main className="page-container">
        <div className="route-stage" key={location.pathname}>
          <Routes location={location}>
            <Route path="/" element={<Home />} />
            <Route path="/url" element={<UrlPage />} />
            <Route path="/file" element={<FilePage />} />
            <Route path="/email" element={<EmailPage />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="*" element={<Home />} />
          </Routes>
        </div>
      </main>
      <footer className="site-footer">
        <div className="page-shell site-footer__inner">
          <div>
            <p className="site-footer__title">Scamurai</p>
            <p>Student-friendly cybersecurity dashboard for high-clarity scam detection demos.</p>
          </div>
          <div className="site-footer__meta">
            <p>Frontend: React + Vite</p>
            <p>Backend: {apiBaseUrl}</p>
          </div>
        </div>
      </footer>
    </div>
  );
}

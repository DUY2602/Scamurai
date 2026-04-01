import { Route, Routes } from "react-router-dom";
import Navbar from "./components/Navbar";
import Home from "./pages/Home";
import UrlPage from "./pages/UrlPage";
import EmailPage from "./pages/EmailPage";
import FilePage from "./pages/FilePage";
import Dashboard from "./pages/Dashboard";

export default function App() {
  return (
    <div className="app-shell">
      <Navbar />
      <main className="page-container">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/url" element={<UrlPage />} />
          <Route path="/file" element={<FilePage />} />
          <Route path="/email" element={<EmailPage />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="*" element={<Home />} />
        </Routes>
      </main>
      <footer className="site-footer">
        <div className="page-shell site-footer__inner">
          <p>Scamurai is a student-friendly cybersecurity dashboard for fast scam detection demos.</p>
          <p>Frontend: React + Vite. Backend: http://localhost:8001</p>
        </div>
      </footer>
    </div>
  );
}

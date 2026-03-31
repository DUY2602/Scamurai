import { motion } from "framer-motion";

import DashboardPreview from "./DashboardPreview.jsx";
import { mockBarLineData, mockDonutData } from "./mockDetectionData.js";

const shellStyle = {
  maxWidth: 1280,
  margin: "0 auto",
  padding: "110px 5% 48px",
  position: "relative",
  zIndex: 1,
};

const cardStyle = {
  padding: 22,
  borderRadius: 18,
  background: "linear-gradient(135deg, rgba(8,20,40,.82) 0%, rgba(4,10,22,.94) 100%)",
  border: "1px solid rgba(0,229,255,.12)",
  boxShadow: "0 0 40px rgba(0,229,255,.06)",
};

function formatNumber(value) {
  return value.toLocaleString();
}

export default function DashboardPage() {
  const totalScans = mockBarLineData.reduce((sum, item) => sum + item.total, 0);
  const maliciousDetections = mockBarLineData.reduce((sum, item) => sum + item.malicious, 0);
  const suspiciousDetections = mockDonutData.find((item) => item.label === "Suspicious")?.value ?? 0;
  const safeDetections = mockDonutData.find((item) => item.label === "Safe")?.value ?? 0;

  return (
    <div style={shellStyle}>
      <motion.section
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", gap: 20, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div>
            <div className="f-mono" style={{ fontSize: 12, color: "rgba(0,229,255,.72)", letterSpacing: 3, marginBottom: 12 }}>
              SENTINEL DASHBOARD
            </div>
            <h1 className="f-orb" style={{ fontSize: "clamp(34px,4.3vw,56px)", color: "#E8F7FF", lineHeight: 1.08 }}>
              Threat telemetry
              <br />
              across every scan lane
            </h1>
          </div>
          <div className="f-mono" style={{ maxWidth: 360, fontSize: 13, lineHeight: 1.8, color: "rgba(200,220,238,.68)" }}>
            A dedicated dashboard page for D3 visualizations. The current version uses mock SQL-shaped data and is ready to be wired to future database-backed GET endpoints.
          </div>
        </div>
      </motion.section>

      <motion.section
        initial={{ opacity: 0, y: 28 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.08, duration: 0.35 }}
        style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16, marginTop: 28 }}
      >
        {[
          { label: "Total Scans", value: formatNumber(totalScans), color: "#00E5FF" },
          { label: "Malicious Detections", value: formatNumber(maliciousDetections), color: "#FF5D73" },
          { label: "Suspicious Detections", value: formatNumber(suspiciousDetections), color: "#FFD166" },
          { label: "Safe Results", value: formatNumber(safeDetections), color: "#00FFA3" },
        ].map((item) => (
          <div key={item.label} style={cardStyle}>
            <div className="f-mono" style={{ fontSize: 11, color: "rgba(130,160,185,.62)", letterSpacing: 1.4 }}>
              {item.label.toUpperCase()}
            </div>
            <div className="f-orb" style={{ fontSize: 34, color: item.color, marginTop: 12 }}>
              {item.value}
            </div>
          </div>
        ))}
      </motion.section>

      <DashboardPreview />
    </div>
  );
}

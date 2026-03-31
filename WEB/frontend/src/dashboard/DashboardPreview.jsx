import { motion } from "framer-motion";

import BarLineChart from "./BarLineChart.jsx";
import DonutChart from "./DonutChart.jsx";
import StackedBarChart from "./StackedBarChart.jsx";
import { mockBarLineData, mockDonutData, mockStackedBarData } from "./mockDetectionData.js";

const cardStyle = {
  padding: 22,
  borderRadius: 18,
  background: "linear-gradient(135deg, rgba(8,20,40,.82) 0%, rgba(4,10,22,.94) 100%)",
  border: "1px solid rgba(0,229,255,.12)",
  boxShadow: "0 0 40px rgba(0,229,255,.06)",
};

const legendStyle = {
  display: "flex",
  alignItems: "center",
  gap: 8,
  fontSize: 11,
  color: "rgba(200,220,238,.72)",
  fontFamily: "JetBrains Mono, monospace",
  letterSpacing: 1.1,
};

function LegendDot({ color }) {
  return <span style={{ width: 10, height: 10, borderRadius: 999, background: color, display: "inline-block" }} />;
}

export default function DashboardPreview() {
  return (
    <motion.section
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.25 }}
      style={{ marginTop: 48 }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: 16, flexWrap: "wrap", marginBottom: 18 }}>
        <div>
          <div className="f-orb" style={{ fontSize: 12, color: "rgba(0,229,255,.72)", letterSpacing: 3.2, marginBottom: 10 }}>
            D3 DASHBOARD PREVIEW
          </div>
          <h2 className="f-orb" style={{ fontSize: "clamp(28px,4vw,42px)", color: "#E8F7FF", lineHeight: 1.15 }}>
            Detection telemetry with mock SQL-shaped data
          </h2>
        </div>
        <div
          className="f-mono"
          style={{
            fontSize: 11,
            color: "rgba(255,214,10,.82)",
            padding: "10px 14px",
            borderRadius: 999,
            border: "1px solid rgba(255,214,10,.25)",
            background: "rgba(255,214,10,.06)",
            alignSelf: "flex-start",
            letterSpacing: 1.2,
          }}
        >
          USING MOCK DATA UNTIL SQL IS READY
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: 18,
        }}
      >
        <div style={{ ...cardStyle, gridColumn: "span 2", minWidth: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
            <div>
              <div className="f-orb" style={{ fontSize: 20, color: "#E8F7FF" }}>Bar + Line</div>
              <div className="f-mono" style={{ fontSize: 11, color: "rgba(200,220,238,.58)", marginTop: 6 }}>
                Bars = total detections, line = malicious detections by day
              </div>
            </div>
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
              <span style={legendStyle}><LegendDot color="rgba(0,229,255,.9)" /> Total</span>
              <span style={legendStyle}><LegendDot color="#FF5D73" /> Malicious</span>
            </div>
          </div>
          <BarLineChart data={mockBarLineData} />
        </div>

        <div style={cardStyle}>
          <div className="f-orb" style={{ fontSize: 20, color: "#E8F7FF", marginBottom: 6 }}>Donut</div>
          <div className="f-mono" style={{ fontSize: 11, color: "rgba(200,220,238,.58)", marginBottom: 18 }}>
            Safe vs suspicious vs malicious distribution
          </div>
          <DonutChart data={mockDonutData} />
          <div style={{ display: "grid", gap: 8, marginTop: 18 }}>
            {mockDonutData.map((item) => (
              <div key={item.label} style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                <span style={legendStyle}><LegendDot color={item.color} /> {item.label}</span>
                <span className="f-mono" style={{ fontSize: 11, color: "rgba(200,220,238,.72)" }}>{item.value}</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ ...cardStyle, gridColumn: "span 2", minWidth: 0 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
            <div>
              <div className="f-orb" style={{ fontSize: 20, color: "#E8F7FF" }}>Stacked Bar</div>
              <div className="f-mono" style={{ fontSize: 11, color: "rgba(200,220,238,.58)", marginTop: 6 }}>
                Safe, suspicious, and malicious detections stacked by asset type
              </div>
            </div>
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
              <span style={legendStyle}><LegendDot color="#00E5FF" /> Safe</span>
              <span style={legendStyle}><LegendDot color="#FFD166" /> Suspicious</span>
              <span style={legendStyle}><LegendDot color="#FF5D73" /> Malicious</span>
            </div>
          </div>
          <StackedBarChart data={mockStackedBarData} />
        </div>
      </div>
    </motion.section>
  );
}

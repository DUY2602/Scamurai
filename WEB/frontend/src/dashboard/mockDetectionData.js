export const mockBarLineData = [
  { date: "03-24", total: 18, malicious: 5 },
  { date: "03-25", total: 24, malicious: 7 },
  { date: "03-26", total: 19, malicious: 4 },
  { date: "03-27", total: 31, malicious: 11 },
  { date: "03-28", total: 27, malicious: 9 },
  { date: "03-29", total: 35, malicious: 14 },
  { date: "03-30", total: 29, malicious: 8 },
];

export const mockDonutData = [
  { label: "Malicious", value: 58, color: "#FF5D73" },
  { label: "Safe", value: 96, color: "#00E5FF" },
  { label: "Suspicious", value: 27, color: "#FFD166" },
];

export const mockStackedBarData = [
  { detectionType: "email", malicious: 24, suspicious: 12, safe: 41 },
  { detectionType: "url", malicious: 18, suspicious: 9, safe: 33 },
  { detectionType: "file", malicious: 16, suspicious: 7, safe: 21 },
];

function getMarkerColor(status) {
  if (status === "threat") {
    return "#dc2626";
  }

  if (status === "suspicious") {
    return "#d97706";
  }

  return "#2563eb";
}

function getMarkerRadius(totalScans) {
  return Math.max(4, Math.min(11, 4 + Number(totalScans || 0)));
}

function projectPoint(longitude, latitude, width, height) {
  const x = ((Number(longitude) + 180) / 360) * width;
  const y = ((90 - Number(latitude)) / 180) * height;
  return { x, y };
}

const continentShapes = [
  "M92 95 C120 70, 180 62, 225 86 C241 96, 250 118, 233 137 C208 165, 171 173, 136 160 C106 149, 83 127, 92 95 Z",
  "M205 173 C224 173, 241 189, 244 210 C247 238, 232 274, 213 304 C196 330, 179 323, 176 292 C173 260, 177 232, 184 204 C188 188, 194 173, 205 173 Z",
  "M286 88 C327 70, 389 73, 446 84 C485 92, 526 112, 526 133 C525 151, 503 162, 477 162 C451 162, 439 173, 432 192 C422 218, 393 228, 367 217 C346 208, 329 212, 311 201 C284 185, 268 150, 271 122 C272 105, 276 94, 286 88 Z",
  "M430 197 C447 187, 473 188, 491 202 C503 212, 501 231, 489 243 C474 259, 446 267, 428 255 C412 244, 410 208, 430 197 Z",
  "M554 247 C580 239, 609 248, 622 265 C635 283, 631 307, 608 316 C582 325, 553 317, 537 298 C525 284, 532 255, 554 247 Z",
];

export default function ThreatMap({ points }) {
  const width = 920;
  const height = 430;

  if (!points?.length) {
    return (
      <div className="empty-card">
        <h3>No map data yet</h3>
        <p>
          Once live detections with public IP geolocation are stored, activity
          dots will appear here.
        </p>
      </div>
    );
  }

  return (
    <div className="map-shell">
      <svg
        aria-label="Global detection activity map"
        className="map-shell__svg"
        viewBox={`0 0 ${width} ${height}`}
        role="img"
      >
        <defs>
          <linearGradient id="mapBg" x1="0%" x2="100%" y1="0%" y2="100%">
            <stop offset="0%" stopColor="#fafdff" />
            <stop offset="100%" stopColor="#eef5ff" />
          </linearGradient>
        </defs>

        <rect fill="url(#mapBg)" height={height} rx="28" width={width} />

        {[0.2, 0.4, 0.6, 0.8].map((ratio) => (
          <line
            key={`lat-${ratio}`}
            stroke="rgba(125, 154, 187, 0.25)"
            strokeDasharray="6 8"
            x1="0"
            x2={width}
            y1={height * ratio}
            y2={height * ratio}
          />
        ))}

        {[0.166, 0.333, 0.5, 0.666, 0.833].map((ratio) => (
          <line
            key={`lng-${ratio}`}
            stroke="rgba(125, 154, 187, 0.18)"
            strokeDasharray="6 10"
            x1={width * ratio}
            x2={width * ratio}
            y1="0"
            y2={height}
          />
        ))}

        <g className="map-shell__continents">
          {continentShapes.map((shape, index) => (
            <path
              key={`continent-${index}`}
              d={shape}
              fill="#d9e7f5"
              opacity="0.92"
              stroke="#b8cce0"
              strokeWidth="2"
              transform="translate(60 35) scale(1.35)"
            />
          ))}
        </g>

        {points.map((point, index) => {
          const { x, y } = projectPoint(point.longitude, point.latitude, width, height);

          return (
            <g key={`${point.longitude}-${point.latitude}-${point.status}-${index}`}>
              <circle
                cx={x}
                cy={y}
                fill={getMarkerColor(point.status)}
                fillOpacity="0.75"
                r={getMarkerRadius(point.total_scans)}
                stroke="#ffffff"
                strokeWidth="2"
              />
              <title>
                {`${point.detection_type} • ${point.status} • ${point.total_scans} scans`}
              </title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

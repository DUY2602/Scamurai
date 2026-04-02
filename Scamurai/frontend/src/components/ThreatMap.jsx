import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
} from "react-simple-maps";

const geoUrl =
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

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
  return Math.max(3, Math.min(10, 3 + Number(totalScans || 0)));
}

export default function ThreatMap({ points }) {
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
      <ComposableMap projection="geoMercator" projectionConfig={{ scale: 125 }}>
        <Geographies geography={geoUrl}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="#dfeaf6"
                stroke="#b7cbe0"
                strokeWidth={0.6}
                style={{
                  default: { outline: "none" },
                  hover: { outline: "none", fill: "#d5e4f5" },
                  pressed: { outline: "none" },
                }}
              />
            ))
          }
        </Geographies>

        {points.map((point, index) => (
          <Marker
            key={`${point.longitude}-${point.latitude}-${point.detection_type}-${index}`}
            coordinates={[point.longitude, point.latitude]}
          >
            <circle
              r={getMarkerRadius(point.total_scans)}
              fill={getMarkerColor(point.status)}
              fillOpacity={0.78}
              stroke="#ffffff"
              strokeWidth={1.2}
            />
            <title>
              {`${point.detection_type} • ${point.status} • ${point.total_scans} scans`}
            </title>
          </Marker>
        ))}
      </ComposableMap>
    </div>
  );
}

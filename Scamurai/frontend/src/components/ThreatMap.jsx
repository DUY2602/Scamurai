import { useEffect, useMemo, useState } from "react";
import { GeoJSON, MapContainer, TileLayer } from "react-leaflet";

function getThreatRateColor(threatRate, totalScans) {
  if (!totalScans) {
    return "#dbe4ee";
  }

  if (threatRate >= 0.6) {
    return "#dc2626";
  }

  if (threatRate >= 0.3) {
    return "#f59e0b";
  }

  return "#16a34a";
}

export default function ThreatMap({
  countryStats = [],
  activeType = "all",
  compact = false,
}) {
  const [worldGeoJson, setWorldGeoJson] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function loadWorldMap() {
      try {
        const response = await fetch("/world-countries.geojson");
        if (!response.ok) {
          throw new Error(`Could not load geojson: ${response.status}`);
        }
        const data = await response.json();
        if (!cancelled) {
          setWorldGeoJson(data);
        }
      } catch (error) {
        if (!cancelled) {
          setWorldGeoJson(null);
        }
      }
    }

    loadWorldMap();
    return () => {
      cancelled = true;
    };
  }, []);

  const countryStatsMap = useMemo(() => {
    return new Map(
      (countryStats || []).map((country) => {
        const normalizedCode = String(country.country_code || "").toUpperCase();
        const typeBucket =
          activeType !== "all" ? country.by_type?.[activeType] || null : null;
        const totalScans =
          activeType === "all"
            ? Number(country.total_scans || 0)
            : Number(typeBucket?.total_scans || 0);
        const threatCount =
          activeType === "all"
            ? Number(country.threat_count || 0)
            : Number(typeBucket?.threat_count || 0);
        const threatRate = totalScans ? threatCount / totalScans : 0;

        return [
          normalizedCode,
          {
            countryName: country.country_name || "Unknown",
            countryCode: normalizedCode,
            totalScans,
            threatCount,
            threatRate,
          },
        ];
      })
    );
  }, [activeType, countryStats]);

  const hasCountryCoverage = [...countryStatsMap.values()].some(
    (country) => Number(country.totalScans || 0) > 0
  );

  if (!hasCountryCoverage) {
    return (
      <div className="empty-card">
        <h3>No country data yet</h3>
        <p>Run detections with geolocation data and the country threat map will appear here.</p>
      </div>
    );
  }

  return (
    <div className={`map-shell map-shell--leaflet${compact ? " map-shell--compact" : ""}`}>
      <MapContainer
        attributionControl={false}
        center={[20, 0]}
        className="map-shell__leaflet"
        preferCanvas
        scrollWheelZoom
        zoom={2}
        zoomControl={!compact}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        {worldGeoJson ? (
          <GeoJSON
            data={worldGeoJson}
            onEachFeature={(feature, layer) => {
              const countryCode = String(
                feature?.properties?.["ISO3166-1-Alpha-2"] || ""
              ).toUpperCase();
              const countryName =
                feature?.properties?.name || countryStatsMap.get(countryCode)?.countryName || "Unknown country";
              const metrics = countryStatsMap.get(countryCode);

              const tooltipHtml = metrics?.totalScans
                ? `
                  <div class="map-popup">
                    <strong>${countryName}</strong>
                    <span>${metrics.totalScans} scans</span>
                    <span>${metrics.threatCount} threats</span>
                    <span>${(metrics.threatRate * 100).toFixed(1)}% threat rate</span>
                  </div>
                `
                : `
                  <div class="map-popup">
                    <strong>${countryName}</strong>
                    <span>No scans in current filter</span>
                  </div>
                `;

              layer.bindTooltip(tooltipHtml, {
                sticky: true,
              });
            }}
            style={(feature) => {
              const countryCode = String(
                feature?.properties?.["ISO3166-1-Alpha-2"] || ""
              ).toUpperCase();
              const metrics = countryStatsMap.get(countryCode);
              const fillColor = getThreatRateColor(metrics?.threatRate || 0, metrics?.totalScans || 0);

              return {
                color: "rgba(255, 255, 255, 0.78)",
                weight: metrics?.totalScans ? 1.1 : 0.7,
                fillColor,
                fillOpacity: metrics?.totalScans ? 0.58 : 0.16,
              };
            }}
          />
        ) : null}
      </MapContainer>
      <div className="map-shell__attribution">
        <a href="https://www.openstreetmap.org/copyright" rel="noreferrer" target="_blank">
          OpenStreetMap
        </a>
      </div>
    </div>
  );
}

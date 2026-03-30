import { useEffect, useRef } from "react";
import * as d3 from "d3";

const SIZE = 320;

export default function DonutChart({ data }) {
  const svgRef = useRef(null);

  useEffect(() => {
    if (!svgRef.current || !data?.length) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const radius = SIZE / 2 - 18;
    const total = d3.sum(data, (d) => d.value);
    const root = svg
      .attr("viewBox", `0 0 ${SIZE} ${SIZE}`)
      .attr("role", "img")
      .attr("aria-label", "Detection risk distribution")
      .append("g")
      .attr("transform", `translate(${SIZE / 2},${SIZE / 2})`);

    const pie = d3.pie().sort(null).value((d) => d.value);
    const arc = d3.arc().innerRadius(radius * 0.58).outerRadius(radius);
    const labelArc = d3.arc().innerRadius(radius * 0.76).outerRadius(radius * 0.76);

    root
      .selectAll("path")
      .data(pie(data))
      .enter()
      .append("path")
      .attr("d", arc)
      .attr("fill", (d) => d.data.color)
      .attr("stroke", "#020812")
      .attr("stroke-width", 3);

    root
      .append("text")
      .attr("text-anchor", "middle")
      .attr("y", -4)
      .attr("fill", "#C8DCEE")
      .style("font-size", "28px")
      .style("font-family", "Orbitron, monospace")
      .text(total);

    root
      .append("text")
      .attr("text-anchor", "middle")
      .attr("y", 18)
      .attr("fill", "rgba(200,220,238,.62)")
      .style("font-size", "11px")
      .style("letter-spacing", "1.8px")
      .style("font-family", "JetBrains Mono, monospace")
      .text("TOTAL EVENTS");

    root
      .selectAll(".slice-label")
      .data(pie(data))
      .enter()
      .append("text")
      .attr("transform", (d) => `translate(${labelArc.centroid(d)})`)
      .attr("text-anchor", "middle")
      .attr("fill", "#020812")
      .style("font-size", "10px")
      .style("font-family", "JetBrains Mono, monospace")
      .text((d) => d.data.value);
  }, [data]);

  return (
    <svg
      ref={svgRef}
      style={{ width: "100%", maxWidth: 320, height: "auto", display: "block", margin: "0 auto" }}
    />
  );
}

import { useEffect, useRef } from "react";
import * as d3 from "d3";

const WIDTH = 680;
const HEIGHT = 320;
const MARGIN = { top: 24, right: 28, bottom: 40, left: 44 };

export default function StackedBarChart({ data }) {
  const svgRef = useRef(null);

  useEffect(() => {
    if (!svgRef.current || !data?.length) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const innerWidth = WIDTH - MARGIN.left - MARGIN.right;
    const innerHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
    const keys = ["safe", "suspicious", "malicious"];
    const colors = {
      safe: "rgba(0,229,255,.84)",
      suspicious: "rgba(255,209,102,.9)",
      malicious: "rgba(255,93,115,.88)",
    };

    const stack = d3.stack().keys(keys);
    const series = stack(data);

    const x = d3.scaleBand().domain(data.map((d) => d.detectionType)).range([0, innerWidth]).padding(0.28);
    const y = d3
      .scaleLinear()
      .domain([0, d3.max(data, (d) => d.safe + d.suspicious + d.malicious) || 0])
      .nice()
      .range([innerHeight, 0]);

    const root = svg
      .attr("viewBox", `0 0 ${WIDTH} ${HEIGHT}`)
      .attr("role", "img")
      .attr("aria-label", "Stacked detections by type with safe, suspicious, and malicious counts")
      .append("g")
      .attr("transform", `translate(${MARGIN.left},${MARGIN.top})`);

    root
      .append("g")
      .call(d3.axisLeft(y).ticks(5))
      .call((g) =>
        g
          .selectAll("text")
          .attr("fill", "rgba(244,250,255,.94)")
          .style("font-size", "11px")
          .style("font-weight", "600")
      )
      .call((g) => g.selectAll("line,path").attr("stroke", "rgba(0,229,255,.14)"))
      .call((g) => g.select(".domain").remove())
      .call((g) =>
        g
          .selectAll(".tick line")
          .clone()
          .attr("x2", innerWidth)
          .attr("stroke-opacity", 1)
          .attr("stroke", "rgba(0,229,255,.08)")
      );

    root
      .append("g")
      .attr("transform", `translate(0,${innerHeight})`)
      .call(d3.axisBottom(x))
      .call((g) =>
        g
          .selectAll("text")
          .attr("fill", "rgba(244,250,255,.94)")
          .style("font-size", "11px")
          .style("font-weight", "600")
      )
      .call((g) => g.selectAll("line,path").attr("stroke", "rgba(0,229,255,.14)"));

    root
      .selectAll("g.layer")
      .data(series)
      .enter()
      .append("g")
      .attr("fill", (d) => colors[d.key])
      .selectAll("rect")
      .data((d) => d)
      .enter()
      .append("rect")
      .attr("x", (d) => x(d.data.detectionType) || 0)
      .attr("y", (d) => y(d[1]))
      .attr("width", x.bandwidth())
      .attr("height", (d) => y(d[0]) - y(d[1]))
      .attr("stroke", "rgba(2,8,18,.55)")
      .attr("stroke-width", 1);

    root
      .selectAll(".total-label")
      .data(data)
      .enter()
      .append("text")
      .attr("x", (d) => (x(d.detectionType) || 0) + x.bandwidth() / 2)
      .attr("y", (d) => y(d.safe + d.suspicious + d.malicious) - 10)
      .attr("text-anchor", "middle")
      .attr("fill", "#F8FCFF")
      .style("font-size", "11px")
      .style("font-weight", "700")
      .style("font-family", "JetBrains Mono, monospace")
      .text((d) => d.safe + d.suspicious + d.malicious);
  }, [data]);

  return <svg ref={svgRef} style={{ width: "100%", height: "auto", display: "block" }} />;
}

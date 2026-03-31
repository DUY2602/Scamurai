import { useEffect, useRef } from "react";
import * as d3 from "d3";

const WIDTH = 640;
const HEIGHT = 300;
const MARGIN = { top: 20, right: 24, bottom: 42, left: 44 };

export default function BarLineChart({ data }) {
  const svgRef = useRef(null);

  useEffect(() => {
    if (!svgRef.current || !data?.length) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const innerWidth = WIDTH - MARGIN.left - MARGIN.right;
    const innerHeight = HEIGHT - MARGIN.top - MARGIN.bottom;

    const root = svg
      .attr("viewBox", `0 0 ${WIDTH} ${HEIGHT}`)
      .attr("role", "img")
      .attr("aria-label", "Detection volume and malicious trend")
      .append("g")
      .attr("transform", `translate(${MARGIN.left},${MARGIN.top})`);

    const x = d3.scaleBand().domain(data.map((d) => d.date)).range([0, innerWidth]).padding(0.24);
    const y = d3
      .scaleLinear()
      .domain([0, d3.max(data, (d) => Math.max(d.total, d.malicious)) || 0])
      .nice()
      .range([innerHeight, 0]);

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
      .selectAll(".bar")
      .data(data)
      .enter()
      .append("rect")
      .attr("x", (d) => x(d.date) || 0)
      .attr("y", (d) => y(d.total))
      .attr("width", x.bandwidth())
      .attr("height", (d) => innerHeight - y(d.total))
      .attr("rx", 8)
      .attr("fill", "rgba(0,229,255,.24)")
      .attr("stroke", "rgba(0,229,255,.5)");

    const line = d3
      .line()
      .x((d) => (x(d.date) || 0) + x.bandwidth() / 2)
      .y((d) => y(d.malicious))
      .curve(d3.curveMonotoneX);

    root
      .append("path")
      .datum(data)
      .attr("fill", "none")
      .attr("stroke", "#FF5D73")
      .attr("stroke-width", 2.5)
      .attr("d", line);

    root
      .selectAll(".point")
      .data(data)
      .enter()
      .append("circle")
      .attr("cx", (d) => (x(d.date) || 0) + x.bandwidth() / 2)
      .attr("cy", (d) => y(d.malicious))
      .attr("r", 4.5)
      .attr("fill", "#020812")
      .attr("stroke", "#FF5D73")
      .attr("stroke-width", 2);
  }, [data]);

  return <svg ref={svgRef} style={{ width: "100%", height: "auto", display: "block" }} />;
}

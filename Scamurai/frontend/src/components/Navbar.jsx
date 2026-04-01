import { NavLink } from "react-router-dom";

const navigationItems = [
  { to: "/", label: "Home", end: true },
  { to: "/url", label: "URL Scan" },
  { to: "/file", label: "File Scan" },
  { to: "/email", label: "Email Scan" },
  { to: "/dashboard", label: "Dashboard" },
];

export default function Navbar() {
  return (
    <header className="site-header">
      <div className="page-shell site-header__inner">
        <NavLink className="brand" to="/">
          <span className="brand__mark">SC</span>
          <span className="brand__text">
            <strong>Scamurai</strong>
            <span>Security scanner dashboard</span>
          </span>
        </NavLink>

        <nav aria-label="Primary navigation" className="nav">
          {navigationItems.map((item) => (
            <NavLink
              key={item.to}
              className={({ isActive }) =>
                `nav-link${isActive ? " is-active" : ""}`
              }
              end={item.end}
              to={item.to}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>
    </header>
  );
}

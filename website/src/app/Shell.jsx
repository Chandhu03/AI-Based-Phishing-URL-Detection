import { useEffect, useRef, useState } from "preact/hooks";
import { useApp } from "./context.js";

const NAV = [
  ["overview", "Overview", "#/overview", "M3 3h6v6H3zM11 3h6v4h-6zM11 9h6v8h-6zM3 11h6v6H3z"],
  ["alerts", "Alert queue", "#/alerts", "M10 3a5 5 0 0 1 5 5v3l2 3H3l2-3V8a5 5 0 0 1 5-5zM8 17h4"],
  ["analyze", "Analyse", "#/analyze", "M8.5 3a5.5 5.5 0 1 1 0 11 5.5 5.5 0 0 1 0-11zM12.5 12.5 17 17"],
  ["analyses", "Analyses", "#/analyses", "M4 4h12M4 8h12M4 12h8M4 16h6M15 13l2 2 3-4"],
  ["investigations", "Investigations", "#/investigations", "M4 3h9l3 3v11H4zM7 8h6M7 11h6M7 14h4"],
  ["indicators", "Indicators", "#/indicators", "M3 10h4l2-6 3 12 2-6h3"],
  ["engine", "Detection engine", "#/engine", "M10 3v3M10 14v3M3 10h3M14 10h3M10 7a3 3 0 1 1 0 6 3 3 0 0 1 0-6z"],
];
const ACTIVE = { analysis: "analyses", investigation: "investigations", alert: "alerts" };

function Mark() {
  return (
    <svg class="mark" viewBox="0 0 28 28" aria-hidden="true" focusable="false">
      <rect x="1" y="1" width="26" height="26" rx="6" class="mark-frame" />
      <path d="M7 10h14M7 14h6M15 14h6M7 18h10" class="mark-lines" />
      <rect x="13" y="12" width="2" height="4" class="mark-cut" />
    </svg>
  );
}

export function Shell({ route, children }) {
  const { storageKind, engine } = useApp();
  const [menu, setMenu] = useState(false);
  const mainRef = useRef(null);
  const menuBtn = useRef(null);
  const firstRender = useRef(true);
  const active = ACTIVE[route.name] ?? route.name;

  // Move focus to the page heading on every navigation after the first load,
  // so screen readers announce the new page. The control that triggered the
  // navigation has usually unmounted, so focus would otherwise fall to <body>.
  useEffect(() => {
    setMenu(false);
    window.scrollTo(0, 0);
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    mainRef.current?.querySelector("[data-page-title]")?.focus({ preventScroll: true });
  }, [route.path]);

  useEffect(() => {
    if (!menu) return undefined;
    const onKey = (e) => {
      if (e.key !== "Escape") return;
      setMenu(false);
      menuBtn.current?.focus();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [menu]);

  return (
    <div class="shell" data-menu={menu ? "open" : "closed"}>
      <a class="skip-link" href="#main" onClick={(e) => { e.preventDefault(); mainRef.current?.focus(); }}>Skip to content</a>
      <aside class="rail" aria-label="Workspace">
        <div class="rail-top">
          <a class="brand" href="/" aria-label="SecureMind Labs website">
            <Mark /><span>SecureMind <span class="brand-sub">Labs</span></span>
          </a>
          <button type="button" ref={menuBtn} class="menu-btn btn btn-quiet btn-sm" aria-expanded={menu} aria-controls="rail-nav" onClick={() => setMenu(!menu)}>Menu</button>
        </div>
        <nav id="rail-nav" class="rail-nav" aria-label="Primary">
          <ul>
            {NAV.map(([key, label, href, d]) => (
              <li key={key}>
                <a href={href} aria-current={active === key ? "page" : undefined}>
                  <svg viewBox="0 0 20 20" aria-hidden="true" focusable="false"><path d={d} /></svg>{label}
                </a>
              </li>
            ))}
          </ul>
          <ul class="rail-secondary">
            <li><a href="#/settings" aria-current={active === "settings" ? "page" : undefined}>Settings and data</a></li>
            <li><a href="/trust/">Privacy and security</a></li>
          </ul>
        </nav>
        <div class="rail-status" aria-label="Workspace status">
          <p><span class="dot" data-ok={storageKind === "indexeddb"} />{storageKind === "indexeddb" ? "Local workspace" : "Temporary workspace"}</p>
          <p class="muted">{storageKind === "indexeddb" ? "Stored in this browser only" : "Browser storage unavailable; nothing is kept"}</p>
          <p><span class="dot" data-ok={engine.ready && !!engine.scorer} />{engine.ready ? (engine.scorer ? "Engine and model loaded" : engine.modelFailed ? "Model failed its check; indicators only" : "Engine loaded, no model") : "Loading engine"}</p>
        </div>
      </aside>
      <main id="main" class="main" tabIndex={-1} ref={mainRef}>
        <div class="main-inner">{children}</div>
      </main>
    </div>
  );
}

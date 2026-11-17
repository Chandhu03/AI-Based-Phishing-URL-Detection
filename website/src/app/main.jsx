
import { Component, render } from "preact";
import { useCallback, useEffect, useMemo, useState } from "preact/hooks";
import { analyzeUrl } from "../engine/analyze.js";
import { loadModel } from "../engine/model.js";
import { loadPsl } from "../engine/psl.js";
import { createIdbStore, createMemoryStore } from "../workspace/stores.js";
import { createWorkspace } from "../workspace/workspace.js";
import { PageHeader } from "./components.jsx";
import { AppContext } from "./context.js";
import { AlertDetail, Alerts } from "./pages/alerts.jsx";
import { Analyses } from "./pages/analyses.jsx";
import { Email } from "./pages/email.jsx";
import { Rules } from "./pages/rules.jsx";
import { Analyze, AnalysisDetail } from "./pages/analyze.jsx";
import { Indicators } from "./pages/indicators.jsx";
import { InvestigationDetail, Investigations } from "./pages/investigations.jsx";
import { Overview } from "./pages/overview.jsx";
import { Engine, Settings } from "./pages/system.jsx";
import { useRoute } from "./router.js";
import { Shell } from "./Shell.jsx";
import { applyTheme, readTheme, saveTheme } from "../ui/theme.js";

applyTheme(readTheme());

function Page({ route }) {
  switch (route.name) {
    case "overview": return <Overview />;
    case "alerts": return <Alerts />;
    case "rules": return <Rules />;
    case "alert": return <AlertDetail id={route.id} />;
    case "email": return <Email />;
    case "analyze": return <Analyze />;
    case "analyses": return <Analyses />;
    case "analysis": return <AnalysisDetail id={route.id} />;
    case "investigations": return <Investigations />;
    case "investigation": return <InvestigationDetail id={route.id} />;
    case "indicators": return <Indicators />;
    case "engine": return <Engine />;
    case "settings": return <Settings />;
    default: return <PageHeader title="Page not found" description="That workspace page does not exist." />;
  }
}

function App({ ws, storageKind }) {
  const route = useRoute();
  const [rev, setRev] = useState(0);
  const [toasts, setToasts] = useState([]);
  const [engine, setEngine] = useState({ ready: false, scorer: null, psl: null });
  const [theme, setThemeState] = useState(readTheme);

  useEffect(() => {
    // A model that fails its integrity check is not used; verdicts then rest
    // on indicators alone and the Engine page says why.
    let modelFailed = false;
    Promise.all([loadPsl(), loadModel().catch(() => { modelFailed = true; return null; })])
      .then(([psl, scorer]) => setEngine({ ready: true, psl, scorer, modelFailed }))
      .catch(() => setEngine({ ready: false, error: true, psl: null, scorer: null }));
  }, []);

  const toast = useCallback((text, kind = "ok") => {
    const id = Math.random();
    setToasts((t) => [...t.slice(-2), { id, text, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 8000 : 4000);
  }, []);

  const value = useMemo(() => ({
    ws, storageKind, rev, bump: () => setRev((r) => r + 1), toast, theme,
    setTheme: (t) => { saveTheme(t); applyTheme(t); setThemeState(t); },
    engine: {
      ...engine,
      pslCommit: engine.psl?.commit ?? "loading",
      analyze: (raw) => analyzeUrl(raw, { psl: engine.psl, scorer: engine.scorer }),
      analyzeAt: (raw, iso) => analyzeUrl(raw, { psl: engine.psl, scorer: engine.scorer, now: () => new Date(iso) }),
    },
  }), [ws, storageKind, rev, toast, engine, theme]);

  return (
    <AppContext.Provider value={value}>
      <Shell route={route}>
        {engine.error && <div class="banner banner-error" role="alert"><p>The analysis engine could not load. Reload the page; if this persists, the bundled rule files may be blocked.</p></div>}
        <PageBoundary key={route.path}><Page route={route} /></PageBoundary>
      </Shell>
      <div class="toasts" role="status" aria-live="polite">
        {toasts.map((t) => <p key={t.id} class="toast" data-kind={t.kind}>{t.text}</p>)}
      </div>
    </AppContext.Provider>
  );
}

/** Keeps one broken page (for example from unexpected stored data) from blanking the app. */
class PageBoundary extends Component {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div class="banner banner-error" role="alert">
        <p>This page could not be displayed. The workspace data it needs may be damaged. Export a backup from Settings, then remove the affected records.</p>
        <a class="btn btn-secondary btn-sm" href="#/settings">Open settings</a>
      </div>
    );
  }
}

// Vite places the module script before the stylesheet link; on slow
// connections the first render could otherwise happen unstyled and shift.
function stylesheetsReady() {
  const pending = [...document.querySelectorAll('link[rel="stylesheet"]')].filter((l) => !l.sheet);
  return Promise.all(pending.map((l) => new Promise((ok) => {
    l.addEventListener("load", ok, { once: true });
    l.addEventListener("error", ok, { once: true });
  })));
}

/** Replace the app with one message; used when the workspace database cannot be used in this tab. */
function Notice({ text, reload = false }) {
  return (
    <div class="banner banner-error" role="alert">
      <p>{text}</p>
      {reload && <button type="button" class="btn btn-secondary btn-sm" onClick={() => location.reload()}>Reload</button>}
    </div>
  );
}

async function start() {
  await stylesheetsReady();
  const root = document.getElementById("app");
  let store;
  try {
    store = await createIdbStore({
      // Another tab still has the previous workspace version open; the upgrade waits for it.
      onBlocked: () => render(<Notice text="The workspace is being updated. Close other SecureMind workspace tabs to continue." />, root),
      // A newer version opened in another tab; this tab's connection is closed, so its changes would fail.
      onVersionChange: () => render(<Notice text="The workspace was updated in another tab. Reload this page to keep working." reload />, root),
    });
  } catch {
    store = createMemoryStore();
  }
  const ws = createWorkspace(store);
  render(<App ws={ws} storageKind={store.kind} />, root);
}

start();

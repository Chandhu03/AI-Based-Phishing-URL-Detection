// Public site behaviour: the mobile menu and the live exhibit on the homepage.
// The exhibit uses the same engine as the workspace and loads it only when a
// visitor analyses a link. Output is built with textContent only.

const toggle = document.querySelector(".nav-toggle");
const nav = document.querySelector("#site-nav");
if (toggle && nav) {
  const set = (open) => {
    toggle.setAttribute("aria-expanded", String(open));
    nav.classList.toggle("is-open", open);
  };
  toggle.addEventListener("click", () => set(toggle.getAttribute("aria-expanded") !== "true"));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
      set(false);
      toggle.focus();
    }
  });
  matchMedia("(min-width: 761px)").addEventListener("change", () => set(false));
}

const form = document.querySelector("#exhibit-form");
if (form) {
  const input = form.querySelector("input");
  const error = document.querySelector("#exhibit-error");
  const status = document.querySelector("#exhibit-status");
  const body = document.querySelector(".exhibit-body");
  let engine;

  async function getEngine() {
    if (!engine) {
      engine = Promise.all([import("../engine/analyze.js"), import("../engine/psl.js"), import("../engine/model.js")])
        .then(async ([a, p, m]) => {
          const [psl, scorer] = await Promise.all([p.loadPsl(), m.loadModel().catch(() => null)]);
          return (raw) => a.analyzeUrl(raw, { psl, scorer });
        })
        .catch((err) => {
          engine = null; // let the next attempt retry instead of reusing the failure
          throw err;
        });
    }
    return engine;
  }

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };

  function render(r) {
    const verdict = document.querySelector("#exhibit-verdict");
    verdict.textContent = r.verdict.label;
    verdict.dataset.level = r.verdict.level;
    document.querySelector("#exhibit-model").textContent = !r.model
      ? (r.modelSkipped === "ip-address" ? "IP address: not scored by the model"
        : r.modelSkipped === "nonstandard-idn" ? "Non-standard characters: not scored by the model"
          : "Model estimate unavailable")
      : r.verdict.band === "not-used"
        ? "Listed brand domain: model estimate not used"
        : `Model estimate ${(r.model.probability * 100).toFixed(1)}%`;
    const spec = document.querySelector("#exhibit-specimen");
    spec.replaceChildren(...r.segments.map((s) => el("span", `seg seg-${s.part}`, s.text)));
    const list = document.querySelector("#exhibit-callouts");
    const shown = r.indicators.filter((i) => i.severity !== "info").slice(0, 3);
    list.replaceChildren(...(shown.length ? shown : [{ severity: "none", title: "No indicators in the link text", detail: "That is not a clean bill of health: the page itself was not visited." }])
      .map((i) => {
        const li = el("li");
        li.dataset.sev = i.severity;
        li.append(el("strong", "", i.title), el("span", "", i.detail));
        return li;
      }));
    const more = r.indicators.filter((i) => i.severity !== "info").length - shown.length;
    status.textContent = `${r.verdict.label}. ${shown.length ? shown.map((i) => i.title).join("; ") : "No indicators found"}${more > 0 ? `; and ${more} more in the workspace` : ""}.`;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.hidden = true;
    let analyze;
    const button = form.querySelector("button[type=submit]");
    const label = button.textContent;
    form.setAttribute("aria-busy", "true");
    button.disabled = true;
    button.textContent = "Loading…";
    try {
      analyze = await getEngine();
    } catch {
      error.textContent = "The analysis engine could not load. Check your connection and try again.";
      error.hidden = false;
      return;
    } finally {
      form.removeAttribute("aria-busy");
      button.disabled = false;
      button.textContent = label;
    }
    const r = analyze(input.value);
    if (!r.ok) {
      error.textContent = r.message;
      error.hidden = false;
      body.dataset.stale = "true";
      input.setAttribute("aria-invalid", "true");
      input.focus();
      return;
    }
    delete body.dataset.stale;
    input.removeAttribute("aria-invalid");
    render(r);
  });
  for (const chip of document.querySelectorAll("[data-example]")) {
    chip.addEventListener("click", () => {
      input.value = chip.dataset.example;
      form.requestSubmit();
    });
  }
}

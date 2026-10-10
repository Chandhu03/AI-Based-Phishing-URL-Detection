import "./styles.css";
import { loadPsl } from "./psl.js";
import { renderFacts } from "./render.js";
import { dissect } from "./url-anatomy.js";

// ---------------------------------------------------------------- navigation
const toggle = document.querySelector(".nav-toggle");
const nav = document.querySelector("#site-nav");

function setNav(open) {
  toggle.setAttribute("aria-expanded", String(open));
  nav.classList.toggle("is-open", open);
}

if (toggle && nav) {
  toggle.addEventListener("click", () => setNav(toggle.getAttribute("aria-expanded") !== "true"));
  nav.addEventListener("click", (event) => {
    if (event.target.closest("a")) setNav(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
      setNav(false);
      toggle.focus();
    }
  });
  window.matchMedia("(min-width: 760px)").addEventListener("change", () => setNav(false));
}

// ---------------------------------------------------------------- dissector
const form = document.querySelector("#dissect-form");

if (form) {
  const input = form.querySelector("#url-input");
  const error = form.querySelector("#url-error");
  const result = document.querySelector("#result");
  const status = document.querySelector("#result-status");
  const idle = document.querySelector("#result-idle");
  const output = document.createElement("div");
  output.className = "result-body";
  result.append(output);

  const showIdle = () => {
    result.dataset.state = "idle";
    output.replaceChildren();
    idle.hidden = false;
  };

  const setError = (message) => {
    error.textContent = message;
    error.hidden = !message;
    if (message) input.setAttribute("aria-invalid", "true");
    else input.removeAttribute("aria-invalid");
  };

  async function run() {
    setError("");
    let psl;
    try {
      psl = await loadPsl();
    } catch {
      showIdle();
      setError("The domain list could not be loaded. Check your connection and try again.");
      return;
    }
    const facts = dissect(input.value, psl);
    if (!facts.ok) {
      showIdle();
      setError(facts.message);
      status.textContent = "";
      input.focus();
      return;
    }
    idle.hidden = true;
    result.dataset.state = "done";
    const notable = renderFacts(output, facts);
    status.textContent = `Dissection complete: ${notable ? `${notable} notable ${notable === 1 ? "observation" : "observations"}` : "no notable observations"}.`;
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    run();
  });

  input.addEventListener("input", () => {
    if (!error.hidden) setError("");
  });

  for (const chip of document.querySelectorAll("[data-example]")) {
    chip.addEventListener("click", () => {
      input.value = chip.dataset.example;
      run();
    });
  }
}

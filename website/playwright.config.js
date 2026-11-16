import { defineConfig, devices } from "@playwright/test";

// End-to-end tests run against the production build, served with the
// production security headers (scripts/serve-dist.mjs). Uses the locally
// installed Chrome; set PW_CHANNEL="" to use Playwright's bundled Chromium.
// Empty PW_CHANNEL selects the bundled Chromium (as in CI).
const channel = process.env.PW_CHANNEL === "" ? undefined : (process.env.PW_CHANNEL ?? "chrome");

export default defineConfig({
  testDir: "e2e",
  timeout: 30_000,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:4317",
    channel,
    trace: "off",
  },
  projects: [
    { name: "desktop", use: { viewport: { width: 1440, height: 900 } } },
    { name: "mobile", use: { ...devices["Pixel 7"], channel } },
  ],
  webServer: {
    command: "node scripts/serve-dist.mjs 4317",
    url: "http://127.0.0.1:4317/",
    reuseExistingServer: false,
    timeout: 20_000,
  },
});

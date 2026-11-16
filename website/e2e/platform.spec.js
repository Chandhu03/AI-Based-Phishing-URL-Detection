import { expect, test } from "@playwright/test";

const PAGES = ["/", "/research/", "/trust/", "/app/"];
const MARKER = "marker-7f3a9c.example";

/** Record console errors, CSP violations and every request a page makes. */
function watch(page) {
  const errors = [];
  const requests = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("request", (r) => requests.push(r.url()));
  return { errors, requests };
}

for (const path of PAGES) {
  test(`${path} loads under the production CSP with no errors and only same-origin requests`, async ({ page, baseURL }) => {
    const w = watch(page);
    const res = await page.goto(path);
    expect(res.status()).toBe(200);
    expect(res.headers()["content-security-policy"]).toContain("connect-src 'none'");
    await page.waitForLoadState("networkidle");
    expect(w.errors).toEqual([]);
    for (const url of w.requests) expect(url.startsWith(baseURL) || url.startsWith("data:")).toBe(true);
  });

  test(`${path} has no horizontal overflow`, async ({ page }) => {
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    const { sw, iw } = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: innerWidth }));
    expect(sw).toBeLessThanOrEqual(iw);
  });
}

test("unknown paths return a real 404 with security headers", async ({ page }) => {
  const res = await page.goto("/no-such-page/");
  expect(res.status()).toBe(404);
  expect(res.headers()["content-security-policy"]).toBeTruthy();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("This page does not exist.");
});

test("the first Tab reaches the skip link", async ({ page, isMobile }) => {
  test.skip(isMobile, "keyboard test runs on desktop");
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.locator(".skip-link")).toBeFocused();
});

test("homepage exhibit analyses locally and renders hostile input as text", async ({ page }) => {
  const w = watch(page);
  await page.goto("/");
  const input = page.locator("#exhibit-input");
  await input.fill(`https://${MARKER}/"><img src=x onerror=alert(1)>`);
  await page.getByRole("button", { name: "Analyse", exact: true }).click();
  await expect(page.locator("#exhibit-error")).toHaveText("The URL contains spaces or other whitespace, which are not allowed.");
  await input.fill(`https://paypal.com.${MARKER}/<svg/onload=alert(1)>`);
  await page.getByRole("button", { name: "Analyse", exact: true }).click();
  await expect(page.locator("#exhibit-verdict")).toHaveText("High risk");
  expect(await page.locator("#exhibit-specimen svg, #exhibit-callouts img").count()).toBe(0);
  expect(w.requests.filter((u) => u.includes(MARKER))).toEqual([]);
  expect(w.errors).toEqual([]);
});

test("workspace journey: analyse, save, investigate, record indicators, persist, export", async ({ page }) => {
  const w = watch(page);
  await page.goto("/app/#/analyze");
  const input = page.locator("#qa-input");
  await expect(page.getByRole("button", { name: "Analyse", exact: true })).toBeEnabled();
  await input.fill(`hxxp://paypal[.]com[.]${MARKER}/login`);
  await page.getByRole("button", { name: "Analyse", exact: true }).click();
  await expect(page.locator(".report .verdict")).toHaveText("High risk");
  await expect(page.locator(".ind-title").first()).toContainText("PayPal name used in a subdomain");

  await page.getByRole("button", { name: "Add to investigation" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Add analysis" }).click();
  await expect(page).toHaveURL(/#\/investigations\/[\w-]+$/);
  await expect(page.locator(".page-title")).toContainText(MARKER);

  await page.getByPlaceholder("What did you find?").fill("Brand only in the subdomain.");
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.locator(".note-body")).toHaveText("Brand only in the subdomain.");
  await page.getByLabel("Status", { exact: true }).selectOption("investigating");
  await expect(page.locator(".timeline")).toContainText("open → investigating");

  // Record indicators from the saved analysis.
  await page.locator(".list-main.mono").first().click();
  await page.getByRole("button", { name: "Record indicators" }).click();
  await page.getByRole("dialog").getByRole("button", { name: /Record 2 indicators/ }).click();
  await page.goto("/app/#/indicators");
  await expect(page.locator("tbody tr")).toHaveCount(2);

  // Data survives a reload (IndexedDB).
  await page.reload();
  await expect(page.locator("tbody tr")).toHaveCount(2);

  // STIX export downloads a file without any network request.
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "STIX 2.1" }).click()]);
  expect(download.suggestedFilename()).toMatch(/\.stix\.json$/);

  expect(w.requests.filter((u) => u.includes(MARKER))).toEqual([]);
  expect(w.errors).toEqual([]);

  // Delete everything.
  page.once("dialog", (d) => d.accept());
  await page.goto("/app/#/settings");
  await page.getByRole("button", { name: "Delete all workspace data" }).click();
  await page.goto("/app/#/overview");
  await expect(page.getByText("Your workspace is empty.")).toBeVisible();
});

test("demo workspace is marked and removable", async ({ page }) => {
  await page.goto("/app/#/overview");
  await page.getByRole("button", { name: "Load demo workspace" }).click();
  await expect(page.getByRole("note")).toContainText("demo records");
  await expect(page.locator(".demo-flag").first()).toBeVisible();
  await page.getByRole("button", { name: "Remove demo records" }).click();
  await expect(page.getByText("Your workspace is empty.")).toBeVisible();
});

test("mobile menu opens and closes with Escape", async ({ page, isMobile }) => {
  test.skip(!isMobile, "mobile only");
  await page.goto("/");
  const toggle = page.locator(".nav-toggle");
  await toggle.click();
  await expect(page.locator("#site-nav")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator("#site-nav")).toBeHidden();
  await expect(toggle).toBeFocused();
});

test("with data, workspace pages do not scroll sideways at 320px", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 700 });
  await page.goto("/app/#/overview");
  await page.getByRole("button", { name: "Load demo workspace" }).click();
  await expect(page.locator(".demo-flag").first()).toBeVisible();
  for (const route of ["#/overview", "#/analyses", "#/indicators", "#/investigations", "#/settings"]) {
    await page.goto(`/app/${route}`);
    await expect(page.locator("[data-page-title]")).toBeVisible();
    const width = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(width, route).toBeLessThanOrEqual(320);
  }
});

test("keyboard focus lands on the new content after actions that replace the trigger", async ({ page }) => {
  await page.goto("/app/#/overview");
  await expect(page.locator(".chip").first()).toBeEnabled();
  await page.locator(".chip").first().click(); // example chip navigates to Analyse
  await expect(page.locator("[data-page-title]")).toBeFocused();
  await page.locator("#qa-input").fill("http://paypal.com.secure-account.tk/login");
  await page.locator("#qa-input").press("Enter");
  await expect(page.locator("#report-verdict")).toBeFocused();
  await page.getByRole("button", { name: "Save to workspace" }).click();
  await expect(page.getByRole("button", { name: "Add to investigation" })).toBeFocused();
});

test("a backup restores into an empty workspace with the same verdicts", async ({ page }) => {
  await page.goto("/app/#/analyze");
  for (const link of ["https://admin:secret@example.com/", "http://3232235777/bank/login", "example.com/login"]) {
    await page.locator("#qa-input").fill(link);
    await page.locator("#qa-input").press("Enter");
    await page.getByRole("button", { name: "Save to workspace" }).click();
    await expect(page.getByRole("button", { name: "Save to workspace" })).toHaveCount(0);
  }
  await page.goto("/app/#/overview");
  await expect(page.locator(".table .verdict")).toHaveCount(3);
  const before = await page.locator(".table .verdict").allTextContents();
  await page.goto("/app/#/settings");
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Export backup" }).click()]);
  const text = await (await download.createReadStream()).toArray().then((c) => Buffer.concat(c).toString("utf8"));
  expect(text).not.toContain("secret");
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Delete all workspace data" }).click();
  await page.locator('input[type="file"]').setInputFiles({ name: "backup.json", mimeType: "application/json", buffer: Buffer.from(text) });
  await expect(page.locator(".toast").last()).toContainText("3 added");
  await page.goto("/app/#/overview");
  await expect(page.locator(".table .verdict")).toHaveCount(before.length);
  expect((await page.locator(".table .verdict").allTextContents()).sort()).toEqual(before.sort());
});

test("batch analysis saves once", async ({ page }) => {
  await page.goto("/app/#/analyze");
  await page.getByRole("button", { name: "Many links" }).click();
  await page.getByLabel("Links, one per line").fill("http://paypal.com.secure-account.tk/login\nhttps://example.org/\nnot a url");
  await page.getByRole("button", { name: "Analyse all" }).click();
  await expect(page.locator("#batch-title")).toBeFocused();
  const save = page.getByRole("button", { name: /Save all to workspace/ });
  await save.click();
  await expect(page.getByRole("button", { name: "Saved to workspace" })).toBeDisabled();
  await page.goto("/app/#/overview");
  await expect(page.locator('[aria-labelledby="r-title"] tbody tr')).toHaveCount(2);
});

test("deleting an indicator from its details closes cleanly", async ({ page }) => {
  await page.goto("/app/#/indicators");
  await page.getByRole("button", { name: "Add indicator" }).click();
  await page.getByRole("dialog").getByLabel("Value").fill("evil[.]example");
  await page.getByRole("dialog").getByRole("button", { name: "Record indicator" }).click();
  await page.getByRole("button", { name: /^Details/ }).click();
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Delete indicator" }).click();
  await expect(page.getByText("No indicators recorded yet.")).toBeVisible();
  await expect(page.locator(".banner-error")).toHaveCount(0);
});

test("analyses page searches, pages, and deletes a selection without touching other records", async ({ page }) => {
  await page.goto("/app/#/analyze");
  await page.getByRole("button", { name: "Many links" }).click();
  const links = Array.from({ length: 29 }, (_, i) => `https://site${i}.example/`).concat("http://paypal.com.secure-account.tk/login");
  await page.getByLabel("Links, one per line").fill(links.join("\n"));
  await page.getByRole("button", { name: "Analyse all" }).click();
  await page.getByRole("button", { name: /Save all to workspace/ }).click();
  await expect(page.getByRole("button", { name: "Saved to workspace" })).toBeDisabled();
  await page.goto("/app/#/analyses");
  await expect(page.locator("#list-status")).toHaveText("Showing 1–25 of 30");
  await page.getByRole("button", { name: "Older" }).click();
  await expect(page.locator("#list-status")).toHaveText("Showing 26–30 of 30");
  await page.getByLabel("Verdict").selectOption("high-risk");
  await expect(page.locator("#list-status")).toHaveText("Showing 1–1 of 1");
  await page.getByLabel("Verdict").selectOption("");
  await page.getByLabel("Search").fill("site1");
  await expect(page.locator("#list-status")).toHaveText("Showing 1–11 of 11");
  await page.getByLabel("Select page").check();
  await expect(page.locator("#list-status")).toContainText("11 selected");
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Delete selected" }).click();
  await expect(page.getByText("No analyses match these filters.")).toBeVisible();
  await expect(page.getByLabel("Search")).toBeFocused(); // focus is not lost when the list empties
  await page.getByLabel("Search").fill("");
  await expect(page.locator("#list-status")).toHaveText("Showing 1–19 of 19");
  await expect(page.locator(".banner-error")).toHaveCount(0);
});

test("a damaged stored record is set aside, reported in Settings and removable", async ({ page }) => {
  const w = watch(page);
  await page.goto("/app/#/overview");
  await page.getByRole("button", { name: "Load demo workspace" }).click();
  await expect(page.locator(".demo-flag").first()).toBeVisible();
  await page.evaluate(() => new Promise((resolve, reject) => {
    const open = indexedDB.open("securemind-workspace");
    open.onsuccess = () => {
      const tx = open.result.transaction("investigations", "readwrite");
      tx.objectStore("investigations").put({ id: "damaged-1", title: 42, history: "x" });
      tx.oncomplete = () => { open.result.close(); resolve(); };
      tx.onerror = () => reject(tx.error);
    };
  }));
  await page.goto("/app/#/investigations");
  await expect(page.locator("[data-page-title]")).toBeVisible();
  await expect(page.locator(".banner-error")).toHaveCount(0);
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await page.goto("/app/#/settings");
  await expect(page.getByText("1 stored record is damaged")).toBeVisible();
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Remove damaged records" }).click();
  await expect(page.getByText("Every stored record passed its check.")).toBeVisible();
  await expect(page.locator("#health-title")).toBeFocused();
  expect(w.errors).toEqual([]);
});

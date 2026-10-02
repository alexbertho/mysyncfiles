// Browser UI/transport regression suite. The backend is a fixture and the
// loopback HTTP server exercises real CORS; cryptography runs in web_status_flow.
// Run with Playwright installed separately: NODE_PATH=/path/to/node_modules node tests/web_status_browser.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const {chromium, firefox} = require("playwright");
const origin = "https://sync.example.test";
const id = "a".repeat(64);
const root = path.join(__dirname, "../src/server");
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' http://127.0.0.1:47831; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
let mode;
let verified;
let probes;
let challenges;
const sockets = new Set();
const loopback = http.createServer((req, res) => {
  assert.equal(req.headers.origin, origin);
  assert.equal(req.headers.cookie, undefined);
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "X-MySync-Bridge, X-MySync-Challenge");
    res.setHeader("Access-Control-Allow-Private-Network", "true");
    res.writeHead(204).end(); return;
  }
  assert.equal(req.headers["x-mysync-bridge"], "1");
  res.setHeader("Content-Type", "application/json");
  if (!req.headers["x-mysync-challenge"]) {
    probes++;
    if (mode === "waiting") return;
    res.writeHead(401).end(JSON.stringify({error: "challenge_required"}));
    return;
  }
  assert.equal(req.headers["x-mysync-challenge"], "signed-test-ticket");
  verified = mode === "recognized" || mode === "lost_ack";
  if (mode === "lost_ack") { req.socket.destroy(); return; }
  res.end(JSON.stringify({challenge_id: "invented", device_name: "Local impostor"}));
});
loopback.on("connection", socket => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });

async function run(type, name) {
  const executablePath = name === "chromium" ? process.env.MYSYNC_CHROMIUM : process.env.MYSYNC_FIREFOX;
  const browser = await type.launch({headless: true, ...(executablePath ? {executablePath} : {})});
  try {
    console.log(`${name} ${browser.version()}`);
    for (const scenario of ["recognized", "impostor", "lost_ack", "waiting", "denied"]) {
      mode = scenario; verified = false; probes = 0; challenges = 0;
      const context = await browser.newContext();
      const page = await context.newPage();
      const errors = [];
      if (process.env.MYSYNC_BROWSER_DEBUG) {
        page.on("console", msg => console.log(msg.type(), msg.text()));
        page.on("requestfailed", req => console.log("request failed", req.url(), req.failure()));
      }
      page.on("pageerror", error => errors.push(error.message));
      if (name === "chromium") {
        if (scenario !== "denied") await context.grantPermissions(["local-network-access"], {origin});
        const cdp = await context.newCDPSession(page);
        const {targetInfo} = await cdp.send("Target.getTargetInfo");
        let permissions = 0;
        for (const permission of ["local-network-access", "loopback-network", "local-network"]) {
          try {
            await cdp.send("Browser.setPermission", {permission: {name: permission}, setting: scenario === "denied" ? "denied" : "granted", origin, browserContextId: targetInfo.browserContextId});
            permissions++;
          } catch (_) { /* Chromium versions expose different permission names. */ }
        }
        assert.ok(permissions > 0, "at least one native LNA permission must be available");
      } else if (scenario === "denied") {
        // Firefox versions before LNA support: cover the optional permission UI
        // without claiming this is an end-to-end native permission test.
        await page.addInitScript(() => {
          navigator.permissions.query = async () => ({state: "denied"});
        });
        await context.route("http://127.0.0.1:47831/**", route => route.abort());
        await context.route("http://[::1]:47831/**", route => route.abort());
      }
      await context.route(`${origin}/**`, async route => {
        const url = new URL(route.request().url());
        const files = {"/status": ["status.html", "text/html"], "/status.js": ["status.js", "text/javascript"], "/status.css": ["status.css", "text/css"]};
        if (files[url.pathname]) {
          const [file, contentType] = files[url.pathname];
          await route.fulfill({contentType, headers: {"Content-Security-Policy": csp, "Cache-Control": "no-store"}, body: fs.readFileSync(path.join(root, file))});
        } else if (url.pathname === "/v1/web/status/challenges") {
          challenges++;
          assert.ok(probes > 0, "probe must precede challenge issuance");
          assert.equal(route.request().headers()["x-mysync-web"], "1");
          await route.fulfill({json: {challenge_id: id, ticket: "signed-test-ticket", expires_at: Math.floor(Date.now()/1000)+60}});
        } else {
          assert.equal(url.pathname, `/v1/web/status/challenges/${id}`);
          const time = Math.floor(Date.now()/1000);
          await route.fulfill(verified ? {json: {challenge_id: id, device_id: 42, device_name: "Device <script>fixture</script>", verified_at: time,
            presence_expires_at: time+120, status: {client_version: "0.3.6", api_version: 1, daemon_state: "idle", communication: "authenticated", observed_at: time, last_authenticated_at: time}}}
            : {status: 202, json: {error: "pending"}});
        }
      });
      await page.goto(`${origin}/status`);
      await page.locator("#verify").click();
      if (scenario === "waiting") {
        await page.waitForFunction(() => document.getElementById("message").textContent.includes("En attente de l’accès local"));
        assert.equal(challenges, 0);
        await page.locator("#cancel").click();
        await page.waitForFunction(() => document.getElementById("message").textContent === "Vérification annulée.");
        assert.equal(challenges, 0);
      } else {
        await page.waitForFunction(() => !document.getElementById("verify").disabled);
        const text = await page.locator("#message").textContent();
        if (scenario === "recognized" || scenario === "lost_ack") {
          assert.match(text, /Machine reconnue/);
          assert.match(await page.locator("#result").textContent(), /Device <script>fixture<\/script>/);
          assert.equal(await page.locator("#result script").count(), 0);
        } else if (scenario === "denied") {
          assert.match(text, /Permission d’accès local refusée/);
          assert.equal(challenges, 0);
          assert.equal(probes, 0);
        } else {
          assert.match(text, /aucune machine vérifiée/);
          assert.equal(await page.locator("#result").isVisible(), false);
        }
      }
      assert.deepEqual(errors, []);
      await context.close();
      for (const socket of sockets) socket.destroy();
      console.log(`  ${scenario}: passed`);
    }
  } finally { await browser.close(); }
}

(async () => {
  await new Promise(resolve => loopback.listen(47831, "127.0.0.1", resolve));
  try {
    if (process.env.MYSYNC_BROWSER !== "firefox") await run(chromium, "chromium");
    if (process.env.MYSYNC_BROWSER !== "chromium") await run(firefox, "firefox");
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => loopback.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

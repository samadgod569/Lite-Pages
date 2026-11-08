// Cloudflare Worker: SSR renderer using Cloudflare Browser Rendering (headless Chrome).
// Same /render API the platform already calls, so just set  SSR_URL=https://<this worker>  in /platform/.env
//
//  Request  (POST /render, header x-admin-key):  { html, url, cookies:{}, cpuMs, ramMb, wallMs, settleMs }
//  Response: { success, html, url, logs[], errors[], settled, resources:{ cpuTimeMs, peakRamMb, source } }
import puppeteer from "@cloudflare/puppeteer";

const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
const clamp = (v, min, max, d) => (Number.isFinite(Number(v)) ? Math.min(max, Math.max(min, Number(v))) : d);

export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname === "/health") return json({ ok: true });
    if (u.pathname !== "/render" || request.method !== "POST") return json({ success: false, error: "Not found" }, 404);
    if (!env.ADMIN_KEY || request.headers.get("x-admin-key") !== env.ADMIN_KEY) return json({ success: false, error: "Unauthorized" }, 401);

    let b;
    try { b = await request.json(); } catch { return json({ success: false, error: "Invalid JSON" }, 400); }
    if (typeof b.html !== "string" || typeof b.url !== "string") return json({ success: false, error: "html and url are required" }, 400);
    let origin;
    try { const p = new URL(b.url); if (!/^https?:$/.test(p.protocol)) throw 0; origin = p.origin; } catch { return json({ success: false, error: "url must be http(s)" }, 400); }

    const wallMs = clamp(b.wallMs, 1000, 30000, 8000);
    const settleMs = clamp(b.settleMs, 0, 10000, 1500);
    const t0 = Date.now();
    const errors = [], logs = [];
    let browser, timer;

    try {
      // A fresh browser per render: slower than reusing one, but pages from different apps never share cookies or storage.
      browser = await puppeteer.launch(env.BROWSER);
      const page = await browser.newPage();
      page.on("pageerror", (e) => errors.push(String((e && e.message) || e).slice(0, 300)));
      page.on("console", (m) => { if (m.type() === "error") logs.push("[error] " + m.text().slice(0, 300)); });

      // The first navigation is answered with the HTML we were given, so the page has its real origin.
      await page.setRequestInterception(true);
      let served = false;
      page.on("request", (req) => {
        if (!served && req.isNavigationRequest()) {
          served = true;
          return req.respond({ status: 200, contentType: "text/html; charset=utf-8", body: b.html });
        }
        if (["image", "media", "font"].includes(req.resourceType())) return req.abort();
        return req.continue();
      });

      const list = Object.entries(b.cookies || {}).map(([name, value]) => ({ name, value: String(value), url: origin }));
      if (list.length) await page.setCookie(...list);

      const work = (async () => {
        await page.goto(b.url, { waitUntil: "domcontentloaded", timeout: wallMs });
        const settled = await page.waitForNetworkIdle({ idleTime: 300, timeout: settleMs }).then(() => true, () => false);
        return { settled, html: await page.content() };
      })();
      const wall = new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error("Wall time limit exceeded"), { code: "wall_limit_exceeded" })), wallMs); });
      const r = await Promise.race([work, wall]);

      return json({
        success: true, html: r.html, url: b.url, logs: logs.slice(0, 20), errors: errors.slice(0, 20), settled: r.settled,
        resources: { cpuTimeMs: Date.now() - t0, peakRamMb: 0, source: "wall" }, // wall time stands in for CPU; RAM not measured
      });
    } catch (e) {
      const isWall = e && e.code === "wall_limit_exceeded";
      return json({
        success: false, error: (e && e.message) || "Render failed", code: (e && e.code) || "render_failed",
        resources: { cpuTimeMs: Date.now() - t0, peakRamMb: 0, source: "wall" },
      }, isWall ? 504 : 500);
    } finally {
      clearTimeout(timer);
      if (browser) await browser.close().catch(() => {});
    }
  },
};
    

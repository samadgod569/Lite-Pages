import puppeteer from "@cloudflare/puppeteer";

const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
const clamp = (v, min, max, d) => (Number.isFinite(Number(v)) ? Math.min(max, Math.max(min, Number(v))) : d);
const UA = "CodeMonCrawler/1.0";

function parseHttpUrl(s) {
  try {
    const p = new URL(s);
    if (!/^https?:$/.test(p.protocol)) return null;
    if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|\[::1\])/i.test(p.hostname)) return null;
    return p;
  } catch { return null; }
}

function normalize(u) {
  const p = new URL(u);
  p.hash = "";
  if (p.pathname.length > 1) p.pathname = p.pathname.replace(/\/+$/, "");
  return p.href;
}

const globToRegex = (g) => new RegExp("^" + String(g).replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i");

async function loadRobots(origin) {
  try {
    const res = await fetch(origin + "/robots.txt", { headers: { "user-agent": UA } });
    if (!res.ok) return [];
    const rules = [];
    let applies = false;
    for (const raw of (await res.text()).split("\n")) {
      const line = raw.replace(/#.*/, "").trim();
      const i = line.indexOf(":");
      if (i < 0) continue;
      const key = line.slice(0, i).trim().toLowerCase();
      const val = line.slice(i + 1).trim();
      if (key === "user-agent") applies = val === "*" || val.toLowerCase().includes("codemoncrawler");
      else if (applies && key === "disallow" && val) rules.push(val);
    }
    return rules;
  } catch { return []; }
}

const blockedByRobots = (rules, url) => {
  const p = new URL(url);
  const target = p.pathname + p.search;
  return rules.some((r) => (r.includes("*") || r.endsWith("$") ? globToRegex(r.replace(/\$$/, "") + (r.endsWith("$") ? "" : "*")).test(target) : target.startsWith(r)));
};

async function handleCrawl(request, env) {
  let b;
  try { b = await request.json(); } catch { return json({ success: false, error: "Invalid JSON" }, 400); }

  const start = parseHttpUrl(b.url);
  if (!start) return json({ success: false, error: "url must be a public http(s) URL" }, 400);

  const maxPages = clamp(b.maxPages, 1, 50, 10);
  const maxDepth = clamp(b.maxDepth, 0, 5, 2);
  const concurrency = clamp(b.concurrency, 1, 3, 2);
  const pageTimeout = clamp(b.pageTimeoutMs, 3000, 30000, 12000);
  const totalMs = clamp(b.totalMs, 5000, 55000, 40000);
  const maxChars = clamp(b.maxChars, 500, 100000, 20000);
  const settleMs = clamp(b.settleMs, 0, 5000, 800);
  const format = ["text", "html", "both"].includes(b.format) ? b.format : "text";
  const sameDomain = b.sameDomain !== false;
  const respectRobots = b.respectRobots !== false;
  const include = (Array.isArray(b.include) ? b.include : []).map(globToRegex);
  const exclude = (Array.isArray(b.exclude) ? b.exclude : []).map(globToRegex);

  const deadline = Date.now() + totalMs;
  const robots = respectRobots ? await loadRobots(start.origin) : [];

  const allowed = (url) => {
    const p = new URL(url);
    if (sameDomain && p.hostname !== start.hostname) return false;
    if (/\.(png|jpe?g|gif|webp|svg|ico|pdf|zip|gz|mp3|mp4|webm|css|js|woff2?|ttf)$/i.test(p.pathname)) return false;
    if (include.length && !include.some((r) => r.test(url))) return false;
    if (exclude.some((r) => r.test(url))) return false;
    if (robots.length && blockedByRobots(robots, url)) return false;
    return true;
  };

  const seen = new Set([normalize(start.href)]);
  const queue = [{ url: normalize(start.href), depth: 0 }];
  const pages = [];
  const skipped = [];
  let stoppedBy = "done";
  let browser;

  try {
    browser = await puppeteer.launch(env.BROWSER);

    const crawlOne = async ({ url, depth }) => {
      const page = await browser.newPage();
      try {
        await page.setUserAgent(UA);
        await page.setRequestInterception(true);
        page.on("request", (req) => (["image", "media", "font", "stylesheet"].includes(req.resourceType()) ? req.abort() : req.continue()));

        const res = await page.goto(url, { waitUntil: "domcontentloaded", timeout: Math.min(pageTimeout, Math.max(1000, deadline - Date.now())) });
        if (settleMs) await page.waitForNetworkIdle({ idleTime: 300, timeout: settleMs }).catch(() => {});

        const data = await page.evaluate(() => ({
          title: document.title || "",
          text: document.body ? document.body.innerText : "",
          links: Array.from(document.querySelectorAll("a[href]")).map((a) => a.href),
        }));

        const entry = { url, finalUrl: page.url(), depth, status: res ? res.status() : 0, title: data.title.trim() };
        if (format !== "html") entry.text = data.text.replace(/\n{3,}/g, "\n\n").trim().slice(0, maxChars);
        if (format !== "text") entry.html = (await page.content()).slice(0, maxChars * 3);

        const links = [];
        for (const l of data.links) {
          const p = parseHttpUrl(l);
          if (!p) continue;
          const n = normalize(p.href);
          if (!links.includes(n)) links.push(n);
        }
        entry.links = links.slice(0, 200);
        pages.push(entry);

        if (depth < maxDepth) {
          for (const n of links) {
            if (seen.has(n)) continue;
            seen.add(n);
            if (!allowed(n)) { if (skipped.length < 100) skipped.push(n); continue; }
            queue.push({ url: n, depth: depth + 1 });
          }
        }
      } catch (e) {
        pages.push({ url, depth, error: (e && e.message) || "failed" });
      } finally {
        await page.close().catch(() => {});
      }
    };

    let active = 0;
    await new Promise((resolve) => {
      const pump = () => {
        if (Date.now() >= deadline) { if (queue.length) stoppedBy = "time_limit"; queue.length = 0; }
        while (active < concurrency && queue.length && pages.length + active < maxPages) {
          const job = queue.shift();
          active++;
          crawlOne(job).finally(() => { active--; pump(); });
        }
        if (!active && (!queue.length || pages.length >= maxPages)) {
          if (queue.length && pages.length >= maxPages) stoppedBy = "page_limit";
          resolve();
        }
      };
      pump();
    });

    return json({
      success: true,
      start: start.href,
      count: pages.length,
      stoppedBy,
      pages,
      skipped,
      tookMs: totalMs - Math.max(0, deadline - Date.now()),
    });
  } catch (e) {
    return json({ success: false, error: (e && e.message) || "Crawl failed", pages }, 500);
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

async function handleRender(request, env) {
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
    browser = await puppeteer.launch(env.BROWSER);
    const page = await browser.newPage();
    page.on("pageerror", (e) => errors.push(String((e && e.message) || e).slice(0, 300)));
    page.on("console", (m) => { if (m.type() === "error") logs.push("[error] " + m.text().slice(0, 300)); });

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
      resources: { cpuTimeMs: Date.now() - t0, peakRamMb: 0, source: "wall" },
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
}

export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname === "/health") return json({ ok: true });
    if (request.method !== "POST" || (u.pathname !== "/render" && u.pathname !== "/crawl")) return json({ success: false, error: "Not found" }, 404);
    if (!env.ADMIN_KEY || request.headers.get("x-admin-key") !== env.ADMIN_KEY) return json({ success: false, error: "Unauthorized" }, 401);
    return u.pathname === "/crawl" ? handleCrawl(request, env) : handleRender(request, env);
  },
};
        

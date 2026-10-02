import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = fileURLToPath(new URL(".", import.meta.url));
const vectorsPath = process.argv[2];
if (!vectorsPath) {
  console.error("usage: node offline-check.mjs <vectors.json>");
  process.exit(2);
}

const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));
if (vectors.offline !== true) {
  console.error("vectors are not marked offline; live-network fixtures are not accepted here");
  process.exit(2);
}

const types = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".wasm", "application/wasm"],
  [".json", "application/json"],
]);

const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://127.0.0.1");
  const relative = decodeURIComponent(url.pathname).replace(/^\/+/, "");
  if (relative.includes("..")) {
    response.writeHead(403);
    response.end();
    return;
  }
  try {
    const body = readFileSync(join(root, relative));
    response.writeHead(200, { "content-type": types.get(extname(relative)) ?? "application/octet-stream" });
    response.end(body);
  } catch {
    response.writeHead(404);
    response.end();
  }
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
if (address === null || typeof address === "string") {
  throw new Error("offline server did not bind a port");
}

const browser = await chromium.launch();
const page = await browser.newPage();
page.setDefaultTimeout(120_000);
page.on("pageerror", (error) => {
  console.error(`pageerror: ${error.message}`);
});

let failed = false;
try {
  await page.goto(`http://127.0.0.1:${address.port}/index.html`);
  await page.waitForFunction(
    () => ["ok", "fail"].includes(document.documentElement.dataset.status ?? ""),
  );
  const exampleStatus = await page.getAttribute("html", "data-status");
  if (exampleStatus !== "ok") {
    const text = await page.locator("#result").textContent();
    throw new Error(`mnemonic example status ${exampleStatus}: ${text}`);
  }

  await page.goto(`http://127.0.0.1:${address.port}/offline.html`);
  await page.waitForFunction(() => typeof window.runOfflineVectors === "function");
  const results = await page.evaluate((input) => window.runOfflineVectors(input), vectors);
  const failures = [];
  for (const testCase of vectors.cases) {
    const result = results.find((item) => item.id === testCase.id);
    if (!result) {
      failures.push(`${testCase.id}: missing browser result`);
      continue;
    }
    if (testCase.expect === "reject") {
      if (result.ok) failures.push(`${testCase.id}: browser accepted an over-limit or inadequate payment`);
      continue;
    }
    if (!result.ok) {
      failures.push(`${testCase.id}: ${result.error}`);
      continue;
    }
    if (String(result.transactionHex).toLowerCase() !== String(testCase.transactionHex).toLowerCase()) {
      failures.push(`${testCase.id}: browser transaction bytes differ from native Rust`);
    }
  }
  if (failures.length > 0) {
    console.error(failures.join("\n"));
    failed = true;
  } else {
    console.log(`offline browser cases matched native Rust: ${vectors.cases.length}`);
    console.log("mnemonic example status: ok");
  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

if (failed) process.exit(1);

// Test dApp static server (spec/09 §5.7): binds only 127.0.0.1:5173 and [::1]:5173, serves only
// the files directly in this folder, no directory listing, fixed Content-Type table.
import { readFile, stat } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = 5173;
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8" };
const HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

async function handle(request, response) {
  const pathname = (request.url ?? "/").split("?")[0];
  const name = pathname === "/" ? "index.html" : pathname.slice(1);
  const type = TYPES[path.extname(name)];
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { ...HEADERS, Allow: "GET, HEAD" }).end();
    return;
  }
  try {
    if (!/^[A-Za-z0-9_-]+\.[a-z]+$/u.test(name) || type === undefined) throw new Error("not served");
    const file = path.join(ROOT, name);
    if (!(await stat(file)).isFile()) throw new Error("not a file");
    const body = await readFile(file);
    response.writeHead(200, { ...HEADERS, "Content-Type": type, "Content-Length": body.length });
    response.end(request.method === "HEAD" ? undefined : body);
  } catch {
    response.writeHead(404, { ...HEADERS, "Content-Type": "text/plain; charset=utf-8" }).end("Not found\n");
  }
}

for (const host of ["127.0.0.1", "::1"]) {
  createServer(handle)
    .on("error", (error) => console.error(`serve: ${host}: ${error.message}`))
    .listen(PORT, host, () => console.log(`serve: listening on ${host.includes(":") ? `[${host}]` : host}:${PORT}`));
}
console.log(`serve: open http://localhost:${PORT}/`);

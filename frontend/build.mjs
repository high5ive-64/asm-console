// Bundles src/ into dist/ (served by the backend). No inline scripts or styles, so the
// strict Content-Security-Policy (script-src 'self'; style-src 'self') holds.
//
// Asset filenames carry a content hash (app-<hash>.js / .css). index.html is served with
// cache-control: no-cache, so after a rebuild the browser re-fetches index.html, sees the new
// hashed URLs and loads the fresh bundle — it can never serve a stale cached app.js.
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, rmSync, readFileSync, copyFileSync } from "node:fs";
import { basename } from "node:path";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist/assets", { recursive: true });

const result = await build({
  entryPoints: ["src/main.tsx"],
  bundle: true,
  minify: true,
  sourcemap: false,
  format: "esm",
  target: ["es2020"],
  outdir: "dist/assets",
  entryNames: "app-[hash]",
  metafile: true,
  define: { "process.env.NODE_ENV": '"production"' },
  jsx: "automatic",
  loader: { ".svg": "text" },
});

// the hashed JS filename esbuild produced
const jsOut = Object.keys(result.metafile.outputs).find((f) => f.endsWith(".js"));
const jsName = basename(jsOut);

// hash the stylesheet ourselves and write it under a matching hashed name
const css = readFileSync("src/styles.css");
const cssName = `app-${createHash("sha256").update(css).digest("hex").slice(0, 8).toUpperCase()}.css`;
writeFileSync(`dist/assets/${cssName}`, css);

writeFileSync(
  "dist/assets/favicon.svg",
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#2f5bea"/><g transform="translate(1.2 1.2) scale(0.9)" color="#fff"><circle cx="10.5" cy="13.5" r="7" fill="none" stroke="currentColor" stroke-width="2.6" stroke-dasharray="33 11" stroke-dashoffset="-2.5" stroke-linecap="round"/><circle cx="19.6" cy="4.6" r="2.7" fill="currentColor"/></g></svg>`
);

writeFileSync(
  "dist/index.html",
  `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Outsider ASM</title>
<link rel="icon" type="image/svg+xml" href="/assets/favicon.svg">
<link rel="stylesheet" href="/assets/${cssName}">
<script type="module" src="/assets/${jsName}"></script>
</head>
<body><div id="root"></div></body>
</html>
`
);
copyFileSync("src/demo_snapshot.json", "dist/assets/demo_snapshot.json");
console.log(`built dist/ (${jsName}, ${cssName}, + demo_snapshot.json)`);

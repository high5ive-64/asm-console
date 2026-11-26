// Builds a self-contained, static demo into docs/ for GitHub Pages (project site at /<repo>/).
// Asset URLs are RELATIVE (assets/...) so they resolve under the project sub-path. The redacted
// snapshot is bundled into the JS (imported by main-demo.tsx), so docs/ needs no backend.
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { basename } from "node:path";

rmSync("../docs", { recursive: true, force: true });
mkdirSync("../docs/assets", { recursive: true });

const result = await build({
  entryPoints: ["src/main-demo.tsx"],
  bundle: true,
  minify: true,
  sourcemap: false,
  format: "esm",
  target: ["es2020"],
  outdir: "../docs/assets",
  entryNames: "app-[hash]",
  metafile: true,
  define: { "process.env.NODE_ENV": '"production"' },
  jsx: "automatic",
  loader: { ".svg": "text", ".json": "json" },
});

const jsName = basename(Object.keys(result.metafile.outputs).find((f) => f.endsWith(".js")));
const css = readFileSync("src/styles.css");
const cssName = `app-${createHash("sha256").update(css).digest("hex").slice(0, 8).toUpperCase()}.css`;
writeFileSync(`../docs/assets/${cssName}`, css);
writeFileSync(
  "../docs/assets/favicon.svg",
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#2f5bea"/><g transform="translate(1.2 1.2) scale(0.9)" color="#fff"><circle cx="10.5" cy="13.5" r="7" fill="none" stroke="currentColor" stroke-width="2.6" stroke-dasharray="33 11" stroke-dashoffset="-2.5" stroke-linecap="round"/><circle cx="19.6" cy="4.6" r="2.7" fill="currentColor"/></g></svg>`
);
// .nojekyll so GitHub Pages serves the assets/ folder verbatim
writeFileSync("../docs/.nojekyll", "");
writeFileSync(
  "../docs/index.html",
  `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Outsider ASM — Demo (redacted)</title>
<meta name="description" content="Redacted snapshot of an Outsider ASM external attack-surface scan.">
<link rel="icon" type="image/svg+xml" href="assets/favicon.svg">
<link rel="stylesheet" href="assets/${cssName}">
<script type="module" src="assets/${jsName}"></script>
</head>
<body><div id="root"></div></body>
</html>
`
);
console.log(`built docs/ (${jsName}, ${cssName})`);

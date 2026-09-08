/**
 * Bundle the built app into one self-contained HTML file.
 *
 * The point is the Windows classroom: no Node, no npm, no server, no admin
 * rights. Download one file, double-click it, and the whole tool runs from the
 * local filesystem. Because the app already has zero runtime network access,
 * inlining the script and the stylesheet is all it takes.
 *
 * Run with: npm run build:single   (it runs `vite build` for you first)
 */

import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const dist = new URL('../dist/', import.meta.url).pathname;
if (!existsSync(join(dist, 'index.html'))) {
  console.error('dist/index.html not found — run `npm run build` first.');
  process.exit(1);
}

let html = readFileSync(join(dist, 'index.html'), 'utf8');
const assets = readdirSync(join(dist, 'assets'));

const js = assets.find((f) => f.endsWith('.js'));
const css = assets.find((f) => f.endsWith('.css'));
if (!js || !css) {
  console.error('Could not find the built JS and CSS in dist/assets.');
  process.exit(1);
}

const jsSource = readFileSync(join(dist, 'assets', js), 'utf8');
const cssSource = readFileSync(join(dist, 'assets', css), 'utf8');

// Replace the tags Vite emitted with their contents.
//
// Both replacements pass a *function*, not a string: a minified bundle is full
// of "$&" and "$'" sequences, and String.replace would interpret those as
// substitution patterns and silently mangle the output.
//
// The closing-tag escape stops a literal "</script>" inside the bundle from
// ending the element early.
const inlineJs = `<script type="module">${jsSource.replace(/<\/script>/g, '<\\/script>')}</script>`;
const inlineCss = `<style>${cssSource}</style>`;

html = html.replace(new RegExp(`<script[^>]*src="[^"]*${js}"[^>]*></script>`), () => inlineJs);
html = html.replace(new RegExp(`<link[^>]*href="[^"]*${css}"[^>]*>`), () => inlineCss);

if (html.includes('assets/')) {
  console.error('Some asset references were not inlined; the single-file build would be broken.');
  process.exit(1);
}

const out = join(dist, 'pcap-osi-visualizer.html');
writeFileSync(out, html);
const kb = (Buffer.byteLength(html) / 1024).toFixed(0);
console.log(`Wrote dist/pcap-osi-visualizer.html (${kb} KB) — one file, no install, works offline.`);

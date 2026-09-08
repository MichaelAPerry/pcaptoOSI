/**
 * Reshape the built app into the body-only form an Artifact publish expects:
 * no doctype, no <html>/<head>/<body> wrapper, everything inlined.
 *
 * Run after `npm run build`. Output: dist/pcap-osi-artifact.html
 */

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dist = new URL('../dist/', import.meta.url).pathname;
const assets = readdirSync(join(dist, 'assets'));
const js = assets.find((f) => f.endsWith('.js'));
const css = assets.find((f) => f.endsWith('.css'));
if (!js || !css) {
  console.error('Build the app first (npm run build).');
  process.exit(1);
}

const jsSource = readFileSync(join(dist, 'assets', js), 'utf8').replace(/<\/script>/g, '<\\/script>');
const cssSource = readFileSync(join(dist, 'assets', css), 'utf8');

const html = `<title>PCAP-to-OSI Visualizer</title>
<style>
${cssSource}
</style>
<div id="root"></div>
<script type="module">
${jsSource}
</script>
`;

const out = join(dist, 'pcap-osi-artifact.html');
writeFileSync(out, html);
console.log(`Wrote dist/pcap-osi-artifact.html (${(Buffer.byteLength(html) / 1024).toFixed(0)} KB)`);

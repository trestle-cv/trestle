import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = path.resolve(process.argv[2] || "public");
const files = [];

async function walk(directory) {
  for (const name of await readdir(directory)) {
    const full = path.join(directory, name);
    const info = await stat(full);
    if (info.isDirectory()) await walk(full);
    else files.push(full);
  }
}

await walk(root);
const html = files.filter((file) => file.endsWith(".html"));
if (html.length === 0) throw new Error(`no HTML files beneath ${root}`);

const missing = [];
for (const file of html) {
  const source = await readFile(file, "utf8");
  for (const match of source.matchAll(/(?:href|src)="([^"#]+)(?:#[^"]*)?"/g)) {
    const value = match[1];
    if (/^(?:https?:|mailto:|data:)/.test(value)) continue;
    const clean = value.split(/[?#]/, 1)[0];
    if (clean.startsWith("/") && clean !== "/" && !path.extname(clean)) continue;
    let target;
    if (clean.startsWith("/")) target = path.join(root, clean);
    else target = path.resolve(path.dirname(file), clean);
    if (target.endsWith(path.sep)) target = path.join(target, "index.html");
    try {
      await stat(target);
    } catch {
      missing.push(`${path.relative(root, file)} -> ${value}`);
    }
  }
}

if (missing.length) throw new Error(`broken local references:\n${missing.join("\n")}`);

const scripts = files.filter((file) => file.endsWith(".js"));
for (const file of scripts) {
  const source = await readFile(file, "utf8");
  const routeBindings = [...source.matchAll(/querySelector\(['"]\[data-route=[^\]]+\]['"]\)\.addEventListener\(['"]click['"]/g)];
  const counts = new Map();
  for (const binding of routeBindings) counts.set(binding[0], (counts.get(binding[0]) || 0) + 1);
  const duplicates = [...counts.entries()].filter(([, count]) => count > 1);
  if (duplicates.length) {
    throw new Error(`duplicate route renderers in ${path.relative(root, file)}:\n${duplicates.map(([binding, count]) => `${count}x ${binding}`).join("\n")}`);
  }
}

const appCSS = await readFile(path.join(root, "assets/css/style.css"), "utf8");
const appJS = await readFile(path.join(root, "assets/js/script.js"), "utf8");
const appHTML = await readFile(path.join(root, "index.html"), "utf8");
for (const contract of [
  [appCSS, "#administrator-fields[hidden]", "administrator hidden-state CSS"],
  [appCSS, "#postgres-configuration[hidden]", "PostgreSQL hidden-state CSS"],
  [appJS, 'selectedDatabase()==="postgres"', "PostgreSQL setup selection"],
  [appJS, "Test and save the PostgreSQL connection", "database selection submit guard"],
  [appHTML, "assets/js/script.js?v=__TRESTLE_ASSET_VERSION__", "versioned dashboard script"],
  [appHTML, "assets/css/style.css?v=__TRESTLE_ASSET_VERSION__", "versioned dashboard stylesheet"],
]) {
  if (!contract[0].includes(contract[1])) throw new Error(`missing ${contract[2]}`);
}
console.log(`checked ${html.length} HTML pages and ${files.length} files`);

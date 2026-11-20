// Ejecuta las pruebas y genera un sitio estático en dist/ para Azure Static Web Apps.
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";

const r = spawnSync(process.execPath, ["tests/engine.test.js"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
const salida = `${r.stdout || ""}${r.stderr || ""}`;
const ok = r.status === 0;

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

mkdirSync("dist", { recursive: true });
writeFileSync(
  "dist/index.html",
  `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Control de Acceso Lab</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem}
.ok{color:#0a7d2c}.fail{color:#b00020}pre{background:#111;color:#eee;padding:1rem;overflow:auto;border-radius:8px;font-size:.8rem}</style>
</head><body>
<h1>Control de Acceso Lab</h1>
<p class="${ok ? "ok" : "fail"}"><strong>${ok ? "Todas las pruebas pasaron" : "Hay pruebas fallidas"}</strong> &middot; generado ${new Date().toISOString()}</p>
<pre>${esc(salida)}</pre>
</body></html>
`
);

console.log(salida);
process.exit(r.status ?? 1);

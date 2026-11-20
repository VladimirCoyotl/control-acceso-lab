// Ejecuta las pruebas y arma el sitio estático en dist/ (interfaz + motor + resultados) para Azure Static Web Apps.
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist", { recursive: true });
cpSync("public", "dist", { recursive: true });
cpSync("engine", "dist/engine", { recursive: true });

const r = spawnSync(process.execPath, ["tests/engine.test.js"], {
  encoding: "utf8",
  env: { ...process.env, NO_COLOR: "1", RESULTS_FILE: "dist/resultados.json" },
});
const salida = `${r.stdout || ""}${r.stderr || ""}`;
writeFileSync("dist/salida-pruebas.txt", salida);
console.log(salida);

if (r.status !== 0) {
  console.error("Las pruebas fallaron: no se publica.");
  process.exit(r.status ?? 1);
}
console.log("Build OK -> dist/");

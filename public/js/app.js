import * as S from "./state.js";

const root = document.getElementById("app");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const badge = (r) => {
  const ok = r === "PERMITIDO" || r === "PERMITIDA";
  return `<span class="badge ${ok ? "b-ok" : "b-bad"}">${ok ? "✔" : "✖"} ${esc(r)}</span>`;
};
const resultBox = (d, extra = "") => {
  const ok = d.resultado === "PERMITIDO";
  return `<div class="result ${ok ? "ok" : "bad"}" role="status">
    <strong>${ok ? "✔ SOLICITUD PERMITIDA" : "✖ SOLICITUD DENEGADA"}</strong>
    <div>${esc(d.motivo)}</div>
    <div class="small muted">Regla: ${esc(d.reglaId || d.aclReglaId || "—")}${extra}</div></div>`;
};

let session = null;       // { token, user }
let pendingMfa = null;    // { challengeId, code, userId }
let loginError = "";
let view = location.hash.replace("#", "") || "panel";

const NAV = [
  ["panel", "Panel principal"], ["usuarios", "Usuarios"], ["recursos", "Recursos"], ["politicas", "Políticas"],
  ["solicitudes", "Solicitudes"], ["auditoria", "Auditoría", "consultar_auditoria"], ["red", "Red / ACL"],
  ["dispositivos", "Dispositivos IoT"], ["pruebas", "Pruebas"],
];
const can = (op) => session && S.permisosDe(session.user.rol).includes(op);
const isAdmin = () => session?.user.rol === "Administrador";
const horaActual = () => new Date().getHours();

// ---------- Autenticación ----------
function renderLogin() {
  const demo = [...S.identity.users.values()];
  root.innerHTML = `<div class="login">
    <h1>Control de Acceso Lab</h1>
    <p class="muted">Laboratorio universitario · RBAC + ABAC + ReBAC, MFA, ACL de red, IoT y auditoría</p>
    <div class="card">
      ${pendingMfa ? `
        <h2>Verificación MFA</h2>
        <p class="small muted">Se emitió el desafío <b>${esc(pendingMfa.challengeId)}</b>. En producción el código llega a Microsoft Authenticator o similar.</p>
        <div class="note"><b>Simulador de autenticador:</b> tu código es <b>${esc(pendingMfa.code)}</b></div>
        <form id="mfa"><label for="code">Código de 6 dígitos</label><input id="code" inputmode="numeric" autocomplete="one-time-code" required>
        <div class="actions"><button>Verificar</button><button type="button" class="ghost" id="cancel">Cancelar</button></div></form>`
      : `
        <h2>Iniciar sesión</h2>
        <form id="login"><label for="uid">ID de usuario</label><input id="uid" placeholder="USR-001" required autocomplete="username">
        <label for="pw">Contraseña</label><input id="pw" type="password" required autocomplete="current-password">
        <div class="actions"><button>Entrar</button></div></form>`}
      ${loginError ? `<div class="result bad"><strong>✖ ${esc(loginError)}</strong></div>` : ""}
    </div>
    <div class="card"><h3>Usuarios de demostración (datos ficticios)</h3>
      <p class="small muted">Contraseña de todos: <code>${esc(S.DEMO_PASSWORD)}</code>. Excepto Estudiante, todos los roles requieren MFA.</p>
      <div class="tablewrap"><table><tr><th>ID</th><th>Nombre</th><th>Rol</th></tr>
      ${demo.map((u) => `<tr><td>${u.id}</td><td>${esc(u.nombre)}</td><td>${esc(u.rol)}</td></tr>`).join("")}</table></div></div>
  </div>`;

  document.getElementById("login")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const record = S.identity.users.get(document.getElementById("uid").value.trim());
    const r = S.auth.initiateAuthentication(record, document.getElementById("pw").value);
    loginError = "";
    if (r.authenticated) return startSession(r.session);
    if (r.mfaRequired) pendingMfa = { challengeId: r.challengeId, code: r.debugTestCode };
    else loginError = r.reason;
    renderLogin();
  });
  document.getElementById("mfa")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const r = S.auth.completeMfa(pendingMfa.challengeId, document.getElementById("code").value.trim());
    if (r.authenticated) { pendingMfa = null; return startSession(r.session); }
    loginError = r.reason; renderLogin();
  });
  document.getElementById("cancel")?.addEventListener("click", () => { pendingMfa = null; loginError = ""; renderLogin(); });
}

function startSession(s) { session = { token: s.token, user: s.user }; loginError = ""; render(); }

function logout() {
  S.audit.registrarEvento({ tipoEvento: S.AUDIT_EVENT_TYPES.LOGOUT, fuente: "AUTENTICACION", identidad: session.user.id, rol: session.user.rol,
    operacion: "cerrar_sesion", resultado: "PERMITIDO", reglaId: "AUTH-LOGOUT", motivo: "Sesión cerrada por el usuario" });
  S.auth.sessions.delete(session.token);
  session = null; render();
}

// ---------- Estructura ----------
function render() {
  if (!session) return renderLogin();
  const items = NAV.filter(([, , perm]) => !perm || can(perm));
  if (!items.some(([id]) => id === view)) view = "panel";
  root.innerHTML = `<div class="shell"><nav class="side"><div class="brand">🔐 Control de Acceso Lab</div>
    ${items.map(([id, label]) => `<a href="#${id}" class="${id === view ? "active" : ""}">${label}</a>`).join("")}
    <div class="who"><b>${esc(session.user.nombre)}</b><br>${esc(session.user.rol)} · ${esc(session.user.departamento)}<br>
    <button class="ghost" id="logout" style="margin-top:.5rem;color:#fff;border-color:#fff">Cerrar sesión</button></div></nav>
    <main id="view"></main></div>`;
  document.getElementById("logout").onclick = logout;
  views[view](document.getElementById("view"));
}
window.addEventListener("hashchange", () => { view = location.hash.replace("#", "") || "panel"; if (session) render(); });

const flash = (el, html) => { el.innerHTML = html; };
const form = (el) => Object.fromEntries(new FormData(el).entries());
const opts = (arr, sel) => arr.map((v) => `<option ${v === sel ? "selected" : ""}>${esc(v)}</option>`).join("");

// ---------- Vistas ----------
const views = {};

views.panel = (el) => {
  const log = S.engine.decisionsLog;
  const perm = log.filter((d) => d.resultado === "PERMITIDO").length;
  const users = [...S.identity.users.values()];
  const resumen = can("consultar_auditoria") ? S.audit.resumen() : null;
  el.innerHTML = `<h1>Panel principal</h1><p class="muted">Estado del sistema en esta sesión.</p>
  <div class="grid">
    <div class="stat"><b>${users.filter((u) => u.activa).length}/${users.length}</b>usuarios activos</div>
    <div class="stat"><b>${S.allResources().length}</b>recursos protegidos</div>
    <div class="stat"><b>${S.engine.policies.length}</b>políticas ABAC/ReBAC activas</div>
    <div class="stat"><b>${log.length}</b>solicitudes evaluadas<br><span class="small muted">${perm} permitidas · ${log.length - perm} denegadas</span></div>
    <div class="stat"><b>${S.iot.listarDispositivos().length}</b>dispositivos IoT</div>
    ${resumen ? `<div class="stat"><b>${resumen.totalRegistros}</b>eventos de auditoría</div>` : ""}
  </div>
  <div class="card"><h2>Tu sesión</h2><p>Rol <b>${esc(session.user.rol)}</b> · permisos: ${S.permisosDe(session.user.rol).map((p) => `<code>${p}</code>`).join(" ")}</p>
  <p class="small muted">Factores usados: ${esc(S.auth.sessions.get(session.token)?.factorsUsed.join(" + "))}</p></div>
  <div class="card"><h2>Últimas solicitudes de acceso</h2>${decisionTable(log.filter((d) => can("consultar_auditoria") || d.solicitanteId === session.user.id).slice(-6).reverse())}</div>`;
};

function decisionTable(rows) {
  if (!rows.length) return `<p class="muted">Aún no hay solicitudes. Usa la vista <b>Solicitudes</b>.</p>`;
  return `<div class="tablewrap"><table><tr><th>Hora</th><th>Usuario</th><th>Recurso</th><th>Operación</th><th>Resultado</th><th>Regla</th><th>Motivo</th></tr>
  ${rows.map((d) => `<tr><td>${esc(new Date(d.timestamp).toLocaleTimeString())}</td><td>${esc(d.solicitanteId)} (${esc(d.rol)})</td><td>${esc(d.recursoId)}</td>
  <td>${esc(d.operacion)}</td><td>${badge(d.resultado)}</td><td>${esc(d.reglaId)}</td><td>${esc(d.motivo)}</td></tr>`).join("")}</table></div>`;
}

views.usuarios = (el) => {
  const q = S.identity.consultarUsuarios(session.user);
  const users = q.ok ? q.usuarios : [];
  el.innerHTML = `<h1>Usuarios</h1><p class="muted">Administración de identidades y roles. La ocultación de botones no sustituye la validación: cada acción la autoriza el motor.</p>
  <div class="card"><div class="tablewrap"><table><tr><th>ID</th><th>Nombre</th><th>Rol</th><th>Departamento</th><th>Estado</th>${isAdmin() ? "<th>Acciones</th>" : ""}</tr>
  ${users.map((u) => `<tr><td>${u.id}</td><td>${esc(u.nombre)}</td><td>${esc(u.rol)}</td><td>${esc(u.departamento)}</td>
  <td>${u.activa ? '<span class="badge b-ok">Activa</span>' : '<span class="badge b-bad">Deshabilitada</span>'}</td>
  ${isAdmin() ? `<td><div class="inline"><select data-role="${u.id}" aria-label="Nuevo rol de ${u.id}">${opts(S.ROLES, u.rol)}</select>
    <button data-setrole="${u.id}">Asignar</button><button class="ghost" data-toggle="${u.id}">${u.activa ? "Deshabilitar" : "Habilitar"}</button></div></td>` : ""}</tr>`).join("")}
  </table></div><div id="out"></div></div>
  ${isAdmin() ? `<div class="card"><h2>Registrar usuario</h2><form id="nuevo"><div class="row">
    <div><label>Nombre</label><input name="nombre" required maxlength="60"></div>
    <div><label>Rol</label><select name="rol">${opts(S.ROLES)}</select></div>
    <div><label>Departamento</label><input name="departamento" required maxlength="40"></div>
    <div><label>Contraseña</label><input name="password" type="password" required minlength="8"></div>
    <div><button>Registrar</button></div></div></form></div>` : `
  <div class="card"><h2>Prueba de escalamiento de privilegios</h2>
  <p class="muted small">Intenta asignarte el rol Administrador. El motor debe denegarlo y registrar el intento en la auditoría.</p>
  <button class="danger" id="escalar">Intentar convertirme en Administrador</button><div id="esc"></div></div>`}`;

  const out = el.querySelector("#out");
  const show = (r, okMsg) => flash(out, `<div class="result ${r.permitido && r.result?.ok !== false ? "ok" : "bad"}"><strong>${r.permitido && r.result?.ok !== false ? "✔ " + okMsg : "✖ Denegado"}</strong>
    <div>${esc(r.permitido ? (r.result?.error || r.evento.motivo) : r.evento.motivo)}</div></div>`);
  el.querySelectorAll("[data-setrole]").forEach((b) => b.onclick = () => {
    const id = b.dataset.setrole, rol = el.querySelector(`[data-role="${id}"]`).value;
    const r = S.adminAction({ tipo: S.AUDIT_EVENT_TYPES.ROLE_MODIFIED, user: session.user, recursoId: id, operacion: "modificar_usuarios",
      run: () => S.identity.asignarRol(session.user, id, rol), ok: `Rol de ${id} cambiado a ${rol}` });
    show(r, `Rol actualizado a ${rol}`); views.usuarios(el); el.querySelector("#out").innerHTML = out.innerHTML;
  });
  el.querySelectorAll("[data-toggle]").forEach((b) => b.onclick = () => {
    const id = b.dataset.toggle, u = S.identity.users.get(id);
    S.adminAction({ tipo: S.AUDIT_EVENT_TYPES.ROLE_MODIFIED, user: session.user, recursoId: id, operacion: "modificar_usuarios",
      run: () => S.identity.cambiarEstadoCuenta(session.user, id, !u.activa), ok: "Estado de cuenta modificado" });
    views.usuarios(el);
  });
  el.querySelector("#nuevo")?.addEventListener("submit", (e) => {
    e.preventDefault(); const f = form(e.target);
    const r = S.adminAction({ tipo: "CREACION_USUARIO", user: session.user, recursoId: "USUARIOS", operacion: "crear_usuarios",
      run: () => S.identity.registrarUsuario(session.user, f), ok: `Usuario ${f.nombre} registrado` });
    views.usuarios(el); el.querySelector("#out").innerHTML = `<div class="result ${r.result?.ok ? "ok" : "bad"}"><strong>${r.result?.ok ? "✔ Usuario registrado" : "✖ " + esc(r.result?.error || r.evento.motivo)}</strong></div>`;
  });
  el.querySelector("#escalar")?.addEventListener("click", () => {
    const r = S.adminAction({ tipo: S.AUDIT_EVENT_TYPES.ROLE_MODIFIED, user: session.user, recursoId: session.user.id, operacion: "modificar_usuarios",
      run: () => S.identity.asignarRol(session.user, session.user.id, "Administrador") });
    flash(el.querySelector("#esc"), resultBox({ resultado: "DENEGADO", motivo: r.evento.motivo, reglaId: r.evento.reglaId }, " · intento registrado en auditoría"));
  });
};

views.recursos = (el) => {
  const rows = S.allResources();
  el.innerHTML = `<h1>Recursos protegidos</h1>
  <div class="card"><div class="tablewrap"><table><tr><th>ID</th><th>Nombre</th><th>Tipo</th><th>Departamento</th><th>Grupo</th><th>Segmento</th><th>Dirección</th><th>Restringido</th></tr>
  ${rows.map((r) => `<tr><td>${r.id}</td><td>${esc(r.nombre)}</td><td>${esc(r.tipo)}</td><td>${esc(r.departamento)}</td><td>${esc(r.grupoAcademico)}</td>
  <td>${esc(r.segmento)}</td><td>${esc(r.direccion)}</td><td>${r.restringido ? '<span class="badge b-warn">Sí</span>' : "No"}</td></tr>`).join("")}</table></div></div>
  ${isAdmin() ? `<div class="card"><h2>Registrar recurso</h2><form id="nuevo"><div class="row">
   <div><label>ID</label><input name="id" required pattern="[A-Z0-9\\-]{3,20}" placeholder="LAB-COMP-03"></div>
   <div><label>Nombre</label><input name="nombre" required maxlength="60"></div>
   <div><label>Departamento</label><input name="departamento" required maxlength="40"></div>
   <div><label>Grupo académico</label><input name="grupoAcademico" required maxlength="20" placeholder="GRP-CC-503"></div>
   <div><label>Segmento</label><select name="segmento">${opts(Object.values(S.NETWORK_SEGMENTS).map((s) => s.id), "VLAN 30")}</select></div>
   <div><label>Dirección IP</label><input name="direccion" required pattern="\\d{1,3}(\\.\\d{1,3}){3}" placeholder="192.168.30.13"></div>
   <div><label><input type="checkbox" name="restringido"> Restringido</label></div>
   <div><button>Registrar</button></div></div></form><div id="out"></div></div>` : ""}`;
  el.querySelector("#nuevo")?.addEventListener("submit", (e) => {
    e.preventDefault(); const f = form(e.target);
    const dup = S.allResources().some((r) => r.id === f.id);
    const r = S.adminAction({ tipo: "REGISTRO_RECURSO", user: session.user, recursoId: f.id, operacion: "autorizar_solicitudes",
      run: () => { if (dup) return { ok: false, error: "Ya existe un recurso con ese ID" };
        S.resources.push({ ...f, tipo: "recurso", restringido: Boolean(f.restringido) }); return { ok: true }; }, ok: `Recurso ${f.id} registrado` });
    views.recursos(el);
    el.querySelector("#out").innerHTML = `<div class="result ${r.permitido && r.result?.ok ? "ok" : "bad"}"><strong>${r.permitido && r.result?.ok ? "✔ Recurso registrado" : "✖ " + esc(r.result?.error || r.evento.motivo)}</strong></div>`;
  });
};

views.politicas = (el) => {
  const ops = [...new Set(Object.values(S.engine.rolePermissions).flat())];
  el.innerHTML = `<h1>Políticas de autorización</h1><p class="muted">Denegar por defecto: sin regla aplicable, la solicitud se deniega.</p>
  <div class="card"><h2>Matriz RBAC (rol × operación)</h2><div class="tablewrap"><table><tr><th>Operación</th>${S.ROLES.map((r) => `<th>${r}</th>`).join("")}</tr>
  ${ops.map((o) => `<tr><td><code>${o}</code></td>${S.ROLES.map((r) => `<td>${S.permisosDe(r).includes(o) ? "✔" : "—"}</td>`).join("")}</tr>`).join("")}</table></div></div>
  <div class="card"><h2>Políticas ABAC y ReBAC</h2><div class="tablewrap"><table><tr><th>ID</th><th>Tipo</th><th>Operación</th><th>Roles</th><th>Descripción</th><th>Estado</th></tr>
  ${S.allPolicies.map((p) => { const on = !S.disabledPolicies.has(p.id); return `<tr><td>${p.id}</td><td>${p.tipo}</td><td><code>${p.operacion}</code></td><td>${p.roles.join(", ")}</td><td>${esc(p.descripcion)}</td>
   <td>${on ? '<span class="badge b-ok">Activa</span>' : '<span class="badge b-bad">Inactiva</span>'}
   ${isAdmin() ? `<br><button class="ghost" data-pol="${p.id}">${on ? "Desactivar" : "Activar"}</button>` : ""}</td></tr>`; }).join("")}</table></div><div id="out"></div></div>`;
  el.querySelectorAll("[data-pol]").forEach((b) => b.onclick = () => {
    const id = b.dataset.pol, on = S.disabledPolicies.has(id);
    const r = S.adminAction({ tipo: S.AUDIT_EVENT_TYPES.POLICY_MODIFIED, user: session.user, recursoId: id, operacion: "modificar_politicas",
      run: () => S.setPolicyEnabled(id, on), ok: `Política ${id} ${on ? "activada" : "desactivada"}` });
    views.politicas(el);
    el.querySelector("#out").innerHTML = `<div class="result ${r.permitido ? "ok" : "bad"}"><strong>${r.permitido ? "✔" : "✖"} ${esc(r.evento.motivo)}</strong></div>`;
  });
};

views.solicitudes = (el) => {
  const res = S.allResources();
  const ops = ["consultar_recursos", "modificar_recursos", "consultar_auditoria", "administrar_dispositivos", "modificar_politicas", "eliminar_usuarios"];
  el.innerHTML = `<h1>Solicitudes de acceso</h1><p class="muted">Simula una operación. Cada solicitud pasa por autenticación (sesión) y luego por el motor RBAC + ABAC + ReBAC.</p>
  <div class="card"><form id="f"><div class="row">
    <div><label>Recurso</label><select name="recurso">${res.map((r) => `<option value="${r.id}">${r.id} · ${esc(r.nombre)}</option>`).join("")}</select></div>
    <div><label>Operación</label><select name="operacion">${opts(ops)}</select></div>
    <div><label>Hora del día (0-23)</label><input name="hora" type="number" min="0" max="23" value="${horaActual()}"></div>
    <div><label><input type="checkbox" name="confiable" checked> Dispositivo confiable</label></div>
    <div><button>Evaluar solicitud</button></div></div></form><div id="out"></div></div>
  <div class="card"><h2>Mis solicitudes recientes</h2><div id="hist"></div></div>`;
  const hist = () => { el.querySelector("#hist").innerHTML = decisionTable(S.engine.decisionsLog.filter((d) => d.solicitanteId === session.user.id).slice(-8).reverse()); };
  hist();
  el.querySelector("#f").addEventListener("submit", (e) => {
    e.preventDefault(); const f = form(e.target);
    const recurso = res.find((r) => r.id === f.recurso);
    const d = S.auth.authorizeWithSession(session.token, S.engine, { recurso, operacion: f.operacion,
      contexto: { horaAcceso: Number(f.hora), horarioInicio: 8, horarioFin: 18, dispositivoConfiable: Boolean(f.confiable) } });
    flash(el.querySelector("#out"), resultBox(d)); hist();
  });
};

views.auditoria = (el) => {
  const ver = (filtros) => S.audit.consultarRegistros({ solicitante: session.user, accessEngine: S.engine, filtros });
  const base = ver({});
  const types = [...new Set(S.audit.recolectarRegistros().map((r) => r.tipoEvento))];
  el.innerHTML = `<h1>Auditoría</h1><p class="muted">Eventos de autenticación, autorización, red, IoT y administración.</p>
  <div class="card"><form id="f"><div class="row">
    <div><label>Tipo de evento</label><select name="tipoEvento"><option value="">Todos</option>${types.map((t) => `<option>${esc(t)}</option>`).join("")}</select></div>
    <div><label>Resultado</label><select name="resultado"><option value="">Todos</option><option>PERMITIDO</option><option>DENEGADO</option></select></div>
    <div><label>Identidad</label><input name="identidad" placeholder="USR-002"></div>
    <div><button>Filtrar</button></div>
    <div class="inline"><button type="button" class="ghost" id="csv">Exportar CSV</button><button type="button" class="ghost" id="json">Exportar JSON</button></div></div></form>
  <div id="tabla"></div></div>`;
  let actual = base;
  const pintar = (r) => {
    actual = r;
    el.querySelector("#tabla").innerHTML = !r.autorizado ? `<div class="result bad"><strong>✖ ${esc(r.motivo)}</strong></div>` :
      `<p class="small muted">${r.total} registro(s)</p><div class="tablewrap"><table><tr><th>ID</th><th>Fecha</th><th>Identidad</th><th>Tipo</th><th>Recurso</th><th>Operación</th><th>Resultado</th><th>Regla</th><th>Motivo</th></tr>
      ${r.registros.slice().reverse().slice(0, 300).map((x) => `<tr><td>${x.idEvento}</td><td>${esc(new Date(x.timestamp).toLocaleString())}</td><td>${esc(x.identidad)}</td><td>${esc(x.tipoEvento)}</td>
      <td>${esc(x.recursoAfectado)}</td><td>${esc(x.operacion)}</td><td>${["PERMITIDO"].includes(x.resultado) ? badge(x.resultado) : `<span class="badge b-bad">${esc(x.resultado)}</span>`}</td><td>${esc(x.reglaId)}</td><td>${esc(x.motivo)}</td></tr>`).join("")}</table></div>`;
  };
  pintar(base);
  el.querySelector("#f").addEventListener("submit", (e) => {
    e.preventDefault(); const f = form(e.target);
    pintar(ver(Object.fromEntries(Object.entries(f).filter(([, v]) => v))));
  });
  const descargar = (nombre, tipo, contenido) => {
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([contenido], { type: tipo })); a.download = nombre; a.click(); URL.revokeObjectURL(a.href);
  };
  const celda = (v) => { let s = String(v ?? ""); if (/^[=+\-@]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; }; // evita inyección de fórmulas CSV
  el.querySelector("#json").onclick = () => descargar("auditoria.json", "application/json", JSON.stringify(actual.registros || [], null, 2));
  el.querySelector("#csv").onclick = () => {
    const rs = actual.registros || []; const cols = ["idEvento", "timestamp", "identidad", "rol", "tipoEvento", "recursoAfectado", "operacion", "resultado", "reglaId", "motivo"];
    descargar("auditoria.csv", "text/csv", [cols.join(","), ...rs.map((r) => cols.map((c) => celda(r[c])).join(","))].join("\n"));
  };
};

views.red = (el) => {
  const segs = Object.values(S.NETWORK_SEGMENTS);
  const ipDe = (id) => segs.find((s) => s.id === id).subnet.replace(/0\/24$/, "10");
  el.innerHTML = `<h1>Red y reglas ACL</h1>
  <div class="card"><h2>Segmentos</h2><div class="tablewrap"><table><tr><th>VLAN</th><th>Subred</th><th>Descripción</th></tr>
  ${segs.map((s) => `<tr><td>${s.id}</td><td>${s.subnet}</td><td>${esc(s.descripcion)}</td></tr>`).join("")}</table></div></div>
  <div class="card"><h2>Reglas ACL (la primera que coincide se aplica)</h2><div class="tablewrap"><table><tr><th>ID</th><th>Origen</th><th>Destino</th><th>Operaciones</th><th>Roles</th><th>Acción</th></tr>
  ${S.DEFAULT_ACL_RULES.map((r) => `<tr><td>${r.id}</td><td>${r.origenSegmento}</td><td>${r.destinoSegmento}</td><td>${r.operacionesPermitidas.join(", ")}</td><td>${r.rolesPermitidos.join(", ")}</td>
  <td><span class="badge ${r.accion === "PERMIT" ? "b-ok" : "b-bad"}">${r.accion}</span></td></tr>`).join("")}</table></div></div>
  <div class="card"><h2>Simular tráfico</h2><form id="f"><div class="row">
   <div><label>Segmento origen</label><select name="origen">${segs.map((s) => `<option ${s.id === "VLAN 30" ? "selected" : ""}>${s.id}</option>`).join("")}</select></div>
   <div><label>Segmento destino</label><select name="destino">${segs.map((s) => `<option ${s.id === "VLAN 40" ? "selected" : ""}>${s.id}</option>`).join("")}</select></div>
   <div><label>Operación</label><select name="operacion">${opts(["consultar_recursos", "modificar_recursos", "administrar_dispositivos", "consultar_auditoria"])}</select></div>
   <div><label><input type="checkbox" name="confiable" checked> Dispositivo confiable</label></div>
   <div><button>Evaluar tráfico</button></div></div></form><div id="out"></div></div>`;
  el.querySelector("#f").addEventListener("submit", (e) => {
    e.preventDefault(); const f = form(e.target);
    const r = S.acl.evaluarTrafico({ origenSegmento: f.origen, ipOrigen: ipDe(f.origen), destinoSegmento: f.destino, ipDestino: ipDe(f.destino),
      operacion: f.operacion, solicitante: session.user, recurso: { id: `NET-${f.destino}`, departamento: session.user.departamento, restringido: f.destino === "VLAN 50" },
      contexto: { dispositivoConfiable: Boolean(f.confiable), horaAcceso: horaActual() }, accessEngine: S.engine });
    flash(el.querySelector("#out"), resultBox(r, ` · ${esc(r.comunicacion)} · ${esc(r.ipOrigen)} → ${esc(r.ipDestino)}`));
  });
};

views.dispositivos = (el) => {
  const devs = S.iot.listarDispositivos();
  el.innerHTML = `<h1>Dispositivos IoT</h1><p class="muted">Cada operación sobre un dispositivo exige sesión válida y autorización del motor.</p>
  <div class="card"><form id="f"><div class="row">
   <div><label>Dispositivo</label><select name="id">${devs.map((d) => `<option value="${d.id}">${d.id} · ${esc(d.nombre)}</option>`).join("")}</select></div>
   <div><label>Operación</label><select name="operacion">${opts(["consultar_recursos", "modificar_recursos", "administrar_dispositivos"])}</select></div>
   <div><label>Nuevo estado (solo modificar)</label><select name="estado"><option value="">Sin cambio</option><option>en_linea</option><option>fuera_de_linea</option></select></div>
   <div><label>Hora del día</label><input name="hora" type="number" min="0" max="23" value="${horaActual()}"></div>
   <div><label><input type="checkbox" name="confiable" checked> Dispositivo confiable</label></div>
   <div><button>Ejecutar</button></div></div></form><div id="out"></div></div>
  <div class="grid">${devs.map((d) => `<div class="card"><h2>${d.id}</h2><p>${esc(d.nombre)}</p>
   <p class="small muted">${esc(d.tipo)} · ${esc(d.direccion)} · ${esc(d.departamento)} · ${d.restringido ? "restringido" : "no restringido"}</p>
   <p>Estado: <span class="badge ${d.estado === "en_linea" ? "b-ok" : "b-warn"}">${esc(d.estado)}</span></p>
   <pre>${esc(JSON.stringify({ parametros: d.parametros }, null, 1))}</pre></div>`).join("")}</div>`;
  el.querySelector("#f").addEventListener("submit", (e) => {
    e.preventDefault(); const f = form(e.target);
    const r = S.iot.ejecutarOperacionIoT({ deviceId: f.id, operacion: f.operacion, solicitante: session.user, accessEngine: S.engine, authModule: S.auth, sessionToken: session.token,
      contexto: { horaAcceso: Number(f.hora), horarioInicio: 8, horarioFin: 18, dispositivoConfiable: Boolean(f.confiable) }, payload: f.estado ? { estado: f.estado } : {} });
    views.dispositivos(el);
    flash(el.querySelector("#out"), resultBox(r.decision, r.efecto ? ` · efecto: ${esc(JSON.stringify(r.efecto))}` : ""));
  });
};

views.pruebas = async (el) => {
  el.innerHTML = `<h1>Pruebas</h1><p class="muted">Resultados de la ejecución automática (CI) sobre este mismo código, generados en el despliegue.</p><div id="c" class="card">Cargando…</div>`;
  try {
    const [j, t] = await Promise.all([fetch("resultados.json").then((r) => r.json()), fetch("salida-pruebas.txt").then((r) => r.text())]);
    const ok = (x) => x.Esperado.split(" ")[0].toUpperCase() === x.Obtenido;
    el.querySelector("#c").innerHTML = `<h2>Matriz P01–P15 · ${j.matriz.filter(ok).length}/${j.matriz.length} coinciden</h2><p class="small muted">Generado: ${esc(j.generado)}</p>
    <div class="tablewrap"><table><tr><th>ID</th><th>Esperado</th><th>Obtenido</th><th>Coincide</th><th>Motivo</th></tr>
    ${j.matriz.map((x) => `<tr><td>${x.ID}</td><td>${esc(x.Esperado)}</td><td>${badge(x.Obtenido)}</td><td>${ok(x) ? '<span class="badge b-ok">✔ Sí</span>' : '<span class="badge b-bad">✖ No</span>'}</td><td>${esc(x.Motivo)}</td></tr>`).join("")}</table></div>
    <h3>Salida completa</h3><pre>${esc(t)}</pre>`;
  } catch { el.querySelector("#c").innerHTML = `<div class="result bad"><strong>✖ No se encontraron resultados. Ejecuta <code>npm run build</code>.</strong></div>`; }
};

render();

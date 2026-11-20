// Conecta los módulos del motor (engine/) con la interfaz. Todo el estado vive en memoria.
import { IdentityModule, ROLES } from "../engine/identities.js";
import { HybridAccessEngine, ABAC_POLICIES, REBAC_POLICIES } from "../engine/abacRebacPolicies.js";
import { AuthModule } from "../engine/authModule.js";
import { IoTSimulator } from "../engine/iotSimulator.js";
import { NetworkAclEngine, NETWORK_SEGMENTS, DEFAULT_ACL_RULES } from "../engine/networkAcl.js";
import { AuditModule, AUDIT_EVENT_TYPES } from "../engine/auditModule.js";

export { ROLES, ABAC_POLICIES, REBAC_POLICIES, NETWORK_SEGMENTS, DEFAULT_ACL_RULES, AUDIT_EVENT_TYPES };

export const DEMO_PASSWORD = "Demo#2026"; // credencial ficticia solo para la demostración

export const identity = new IdentityModule();
export const engine = new HybridAccessEngine();
export const auth = new AuthModule();
export const iot = new IoTSimulator();
export const acl = new NetworkAclEngine();
export const audit = new AuditModule({ policyEngine: engine, authModule: auth, iotSimulator: iot, aclEngine: acl });

export const allPolicies = [...ABAC_POLICIES, ...REBAC_POLICIES];
export const disabledPolicies = new Set();

export const resources = [
  { id: "LAB-COMP-01", nombre: "Laboratorio de Cómputo 1", tipo: "laboratorio", departamento: "Computación", grupoAcademico: "GRP-CC-501", restringido: false, segmento: "VLAN 30", direccion: "192.168.30.11" },
  { id: "LAB-COMP-02", nombre: "Laboratorio de Cómputo 2", tipo: "laboratorio", departamento: "Computación", grupoAcademico: "GRP-CC-502", restringido: false, segmento: "VLAN 30", direccion: "192.168.30.12" },
  { id: "SRV-CORE-01", nombre: "Servidor de Prácticas", tipo: "servidor", departamento: "Sistemas", grupoAcademico: "GRP-SIS-900", restringido: true, segmento: "VLAN 50", direccion: "192.168.50.10" },
];

// Usuarios ficticios de demostración
const bootstrap = { id: "USR-000", nombre: "Bootstrap", rol: "Administrador", departamento: "Sistemas", activa: true };
const seed = [
  { nombre: "Ana López", rol: "Administrador", departamento: "Sistemas" },
  { nombre: "Carlos Ruiz", rol: "Profesor", departamento: "Computación", grupos: ["GRP-CC-501"] },
  { nombre: "Marta Díaz", rol: "Técnico", departamento: "Sistemas" },
  { nombre: "Luis Pérez", rol: "Estudiante", departamento: "Computación" },
  { nombre: "Sofía Vega", rol: "Auditor", departamento: "Sistemas" },
];
for (const s of seed) {
  const r = identity.registrarUsuario(bootstrap, { ...s, password: DEMO_PASSWORD });
  if (s.grupos) identity.users.get(r.usuario.id).gruposResponsable = s.grupos;
}

export function permisosDe(rol) {
  return engine.rolePermissions[rol] || [];
}

// Ejecuta una operación administrativa: autoriza con el motor, la audita y solo entonces la ejecuta.
export function adminAction({ tipo, user, recursoId, operacion, run, ok = "Operación ejecutada" }) {
  let result = null;
  const evento = audit.ejecutarOperacionAuditada({
    tipoEvento: tipo,
    solicitante: user,
    recursoId,
    operacion,
    accessEngine: engine,
    accionCallback: () => { result = run(); },
    motivoExito: ok,
  });
  return { evento, permitido: evento.resultado === "PERMITIDO", result };
}

export function setPolicyEnabled(id, enabled) {
  const pol = allPolicies.find((p) => p.id === id);
  if (!pol) return;
  const idx = engine.policies.indexOf(pol);
  if (enabled && idx === -1) engine.policies.push(pol);
  if (!enabled && idx !== -1) engine.policies.splice(idx, 1);
  if (enabled) disabledPolicies.delete(id); else disabledPolicies.add(id);
}

export function allResources() {
  const devs = iot.listarDispositivos().map((d) => ({
    id: d.id, nombre: d.nombre, tipo: `IoT/${d.tipo}`, departamento: d.departamento,
    grupoAcademico: d.grupoAcademico, restringido: d.restringido, segmento: "VLAN 40", direccion: d.direccion,
  }));
  return [...resources, ...devs];
}

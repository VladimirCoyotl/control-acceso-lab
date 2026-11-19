import { IdentityModule } from "../engine/identities.js";
import { PolicyEngine } from "../engine/policyEngine.js";
import { HybridAccessEngine } from "../engine/abacRebacPolicies.js";
import { AuthModule } from "../engine/authModule.js";

const modulo = new IdentityModule();

// Usuario inicial de prueba para arrancar el ejemplo
const adminActor = {
  id: "USR-000",
  nombre: "Admin Prueba",
  rol: "Administrador",
  departamento: "Sistemas",
  activa: true,
};

// 1. Registrar usuarios (datos ficticios)
const resAdmin = modulo.registrarUsuario(adminActor, {
  nombre: "Ana López",
  rol: "Administrador",
  departamento: "Sistemas",
  password: "PasswordFicticio123!",
});
const admin = { ...resAdmin.usuario, activa: true };

const resEst = modulo.registrarUsuario(admin, {
  nombre: "Luis Pérez",
  rol: "Estudiante",
  departamento: "Computación",
  password: "PasswordFicticio456!",
});
const estudiante = { ...resEst.usuario, activa: true };

console.log("1. Registro:", { resAdmin, resEst });

// 2. Consultar usuarios
console.log("2. Consultar:", modulo.consultarUsuarios(admin));

// 3. Modificar información
console.log("3. Modificar:", modulo.modificarInformacion(admin, estudiante.id, { departamento: "Redes" }));

// 4. Activar / desactivar cuenta
console.log("4. Desactivar:", modulo.cambiarEstadoCuenta(admin, estudiante.id, false));
console.log("4. Activar:", modulo.cambiarEstadoCuenta(admin, estudiante.id, true));

// 5. Asignar rol
console.log("5. Asignar rol:", modulo.asignarRol(admin, estudiante.id, "Profesor"));

// 6. Consultar permisos por rol
console.log("6. Permisos rol:", modulo.consultarPermisosRol("Profesor"));

// Prueba negativa: Estudiante intenta asignar rol
console.log("Prueba negativa (no admin):", modulo.asignarRol(estudiante, estudiante.id, "Administrador"));

const motor = new PolicyEngine([
  {
    id: "POL-01-LAB-ESTUDIANTE",
    operacion: "consultar_recursos",
    recursoId: "LAB-01",
    roles: ["Estudiante"],
    descripcion: "Estudiante consulta LAB-01 dentro de su departamento",
    condicion: ({ solicitante, recurso, contexto }) => {
      const deptoRecurso = typeof recurso === "object" ? recurso.departamento : contexto.departamentoRecurso;
      if (solicitante.departamento !== deptoRecurso) {
        return { cumple: false, motivo: "Departamento distinto al del recurso" };
      }
      return { cumple: true };
    },
  },
]);

const usuarioActivo = {
  id: "USR-002",
  nombre: "Luis Pérez",
  rol: "Estudiante",
  departamento: "Computación",
  activa: true,
};

const usuarioInactivo = { ...usuarioActivo, activa: false };

console.log("--- 7.4 Motor de autorización ---");

// 1. Permitido con regla y condición cumplida
console.log(
  "Permitido:",
  motor.evaluate({
    solicitante: usuarioActivo,
    recurso: { id: "LAB-01", direccion: "192.168.10.15", departamento: "Computación" },
    operacion: "consultar_recursos",
    fechaHora: new Date().toISOString(),
    contexto: { segmento: "VLAN 30" },
  })
);

// 2. Denegado por defecto (recurso sin regla)
console.log(
  "Sin regla (denegado por defecto):",
  motor.evaluate({
    solicitante: usuarioActivo,
    recurso: { id: "SRV-ADMIN-99", direccion: "192.168.50.10" },
    operacion: "consultar_recursos",
    fechaHora: new Date().toISOString(),
    contexto: {},
  })
);

// 3. Denegado aunque conozca ID y dirección del recurso (sin permiso de rol)
console.log(
  "Conoce ID/IP pero sin permiso:",
  motor.evaluate({
    solicitante: usuarioActivo,
    recurso: { id: "SRV-ADMIN-99", direccion: "192.168.50.10" },
    operacion: "modificar_politicas",
    fechaHora: new Date().toISOString(),
    contexto: {},
  })
);

// 4. Denegado por usuario deshabilitado
console.log(
  "Usuario deshabilitado:",
  motor.evaluate({
    solicitante: usuarioInactivo,
    recurso: { id: "LAB-01", departamento: "Computación" },
    operacion: "consultar_recursos",
    fechaHora: new Date().toISOString(),
    contexto: {},
  })
);

// 5. Registro de decisiones (Comportamiento 6)
console.log("Total decisiones registradas:", motor.obtenerHistorialDecisiones().length);

const hibrido = new HybridAccessEngine();

console.log("--- 7.5 Políticas ABAC y ReBAC ---");

// ABAC 1: Estudiante con mismo departamento -> PERMITIDO
console.log(
  "ABAC-01 Permitido:",
  hibrido.evaluate({
    solicitante: { id: "USR-002", rol: "Estudiante", departamento: "Computación", activa: true },
    recurso: { id: "LAB-01", departamento: "Computación", restringido: false },
    operacion: "consultar_recursos",
    fechaHora: "2026-11-19T10:00:00.000Z",
    contexto: { dispositivoConfiable: true },
  })
);

// ABAC 2: Técnico fuera de horario -> DENEGADO
console.log(
  "ABAC-02 Denegado (horario):",
  hibrido.evaluate({
    solicitante: { id: "USR-003", rol: "Técnico", departamento: "Sistemas", activa: true },
    recurso: { id: "EQ-04", departamento: "Sistemas", restringido: false },
    operacion: "modificar_recursos",
    fechaHora: "2026-11-19T22:00:00.000Z",
    contexto: { horaAcceso: 22, horarioInicio: 8, horarioFin: 18, dispositivoConfiable: true },
  })
);

// ABAC 4: Dispositivo no confiable en recurso restringido -> DENEGADO
console.log(
  "ABAC-04 Denegado (dispositivo no confiable):",
  hibrido.evaluate({
    solicitante: { id: "USR-002", rol: "Estudiante", departamento: "Computación", activa: true },
    recurso: { id: "SRV-SEG-01", departamento: "Computación", restringido: true },
    operacion: "consultar_recursos",
    fechaHora: "2026-11-19T10:00:00.000Z",
    contexto: { dispositivoConfiable: false },
  })
);

// ReBAC: Profesor sobre grupo de su responsabilidad -> PERMITIDO
console.log(
  "ReBAC Permitido (grupo propio):",
  hibrido.evaluate({
    solicitante: {
      id: "USR-004",
      rol: "Profesor",
      departamento: "Computación",
      activa: true,
      gruposResponsable: ["GRP-CC-501"],
    },
    recurso: { id: "MAT-501", grupoAcademico: "GRP-CC-501", restringido: false },
    operacion: "modificar_recursos",
    fechaHora: "2026-11-19T11:00:00.000Z",
    contexto: { dispositivoConfiable: true },
  })
);

// ReBAC: Profesor sobre grupo de otro profesor -> DENEGADO
console.log(
  "ReBAC Denegado (grupo ajeno):",
  hibrido.evaluate({
    solicitante: {
      id: "USR-004",
      rol: "Profesor",
      departamento: "Computación",
      activa: true,
      gruposResponsable: ["GRP-CC-501"],
    },
    recurso: { id: "MAT-502", grupoAcademico: "GRP-CC-502", restringido: false },
    operacion: "modificar_recursos",
    fechaHora: "2026-11-19T11:00:00.000Z",
    contexto: { dispositivoConfiable: true },
  })
);

const idMod = new IdentityModule();
const authMod = new AuthModule({ provider: "Microsoft Entra ID (Flujo de prueba)" });
const motorAuth = new HybridAccessEngine([
  {
    id: "POL-AUDITORIA-LECTURA",
    operacion: "consultar_auditoria",
    recursoId: "*",
    roles: ["Auditor", "Administrador"],
    descripcion: "Consulta de registros de auditoría para rol autorizado",
  },
]);

const adminSeed = {
  id: "USR-000",
  nombre: "Admin Inicial",
  rol: "Administrador",
  departamento: "Sistemas",
  activa: true,
};

const creadoAuditor = idMod.registrarUsuario(adminSeed, {
  nombre: "Carla Ruiz",
  rol: "Auditor",
  departamento: "Sistemas",
  password: "ClaveFicticiaSegura#2026",
});

const registroInternoAuditor = idMod.users.get(creadoAuditor.usuario.id);

console.log("--- 7.6 Autenticación y MFA ---");

// 1. Usuario intenta recurso protegido sin completar MFA
const inicioAuth = authMod.initiateAuthentication(registroInternoAuditor, "ClaveFicticiaSegura#2026");
console.log("1. Inicio auth (MFA pendiente):", inicioAuth);

const sinCompletarMfa = authMod.authorizeWithSession(null, motorAuth, {
  recurso: { id: "LOG-SISTEMA-01" },
  operacion: "consultar_auditoria",
});
console.log("2. Sin completar MFA / sin sesión:", sinCompletarMfa);

// 3. Completa MFA con código incorrecto
const mfaFallido = authMod.completeMfa(inicioAuth.challengeId, "000000");
console.log("3. MFA código incorrecto:", mfaFallido);

// 4. Completa MFA con código correcto -> autenticado
const mfaOk = authMod.completeMfa(inicioAuth.challengeId, inicioAuth.debugTestCode);
console.log("4. MFA completado:", mfaOk);

// 5. Autenticado consulta auditoría (permitido por rol Auditor)
const tokenValido = mfaOk.session?.token;
console.log(
  "5. Autenticado + autorizado (consultar_auditoria):",
  authMod.authorizeWithSession(tokenValido, motorAuth, {
    recurso: { id: "LOG-SISTEMA-01" },
    operacion: "consultar_auditoria",
  })
);

// 6. Autenticado pero SIN permiso para modificar políticas (autenticación != autorización)
console.log(
  "6. Autenticado pero NO autorizado (modificar_politicas):",
  authMod.authorizeWithSession(tokenValido, motorAuth, {
    recurso: { id: "POL-01" },
    operacion: "modificar_politicas",
  })
);
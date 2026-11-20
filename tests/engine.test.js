import { IdentityModule } from "../engine/identities.js";
import { PolicyEngine } from "../engine/policyEngine.js";
import { HybridAccessEngine } from "../engine/abacRebacPolicies.js";
import { AuthModule } from "../engine/authModule.js";
import { IoTSimulator } from "../engine/iotSimulator.js";
import { NetworkAclEngine } from "../engine/networkAcl.js";
import { AuditModule, AUDIT_EVENT_TYPES } from "../engine/auditModule.js";

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

const iotSim = new IoTSimulator();

console.log("--- 7.7 Simulación de dispositivos IoT ---");

// 1. Estudiante de Computación consulta sensor de su departamento -> PERMITIDO
console.log(
  "IoT 1 (Estudiante consulta sensor de su depto):",
  iotSim.ejecutarOperacionIoT({
    deviceId: "IOT-SENS-01",
    operacion: "consultar_recursos",
    solicitante: {
      id: "USR-002",
      rol: "Estudiante",
      departamento: "Computación",
      activa: true,
    },
    accessEngine: hibrido,
    fechaHora: "2026-11-19T10:00:00.000Z",
    contexto: { dispositivoConfiable: true },
  })
);

// 2. Dispositivo no confiable intenta consultar controlador restringido -> DENEGADO (ABAC-04)
console.log(
  "IoT 2 (Dispositivo no confiable en controlador restringido):",
  iotSim.ejecutarOperacionIoT({
    deviceId: "IOT-CTRL-02",
    operacion: "consultar_recursos",
    solicitante: {
      id: "USR-003",
      rol: "Técnico",
      departamento: "Sistemas",
      activa: true,
    },
    accessEngine: hibrido,
    fechaHora: "2026-11-19T10:00:00.000Z",
    contexto: { dispositivoConfiable: false },
  })
);

// 3. Técnico modifica parámetros dentro de horario autorizado -> PERMITIDO
console.log(
  "IoT 3 (Técnico modifica en horario autorizado):",
  iotSim.ejecutarOperacionIoT({
    deviceId: "IOT-SENS-01",
    operacion: "modificar_recursos",
    solicitante: {
      id: "USR-003",
      rol: "Técnico",
      departamento: "Computación",
      activa: true,
    },
    accessEngine: hibrido,
    fechaHora: "2026-11-19T11:00:00.000Z",
    contexto: { horaAcceso: 11, horarioInicio: 8, horarioFin: 18, dispositivoConfiable: true },
    payload: { parametros: { intervaloSegundos: 60 } },
  })
);

// 4. Profesor intenta modificar cámara de un grupo que NO administra -> DENEGADO (ReBAC)
console.log(
  "IoT 4 (Profesor en cámara de grupo ajeno):",
  iotSim.ejecutarOperacionIoT({
    deviceId: "IOT-CAM-03",
    operacion: "modificar_recursos",
    solicitante: {
      id: "USR-004",
      rol: "Profesor",
      departamento: "Computación",
      activa: true,
      gruposResponsable: ["GRP-CC-501"],
    },
    accessEngine: hibrido,
    fechaHora: "2026-11-19T11:00:00.000Z",
    contexto: { dispositivoConfiable: true },
  })
);

// 5. Operación sin regla o sin permiso sobre dispositivo IoT -> DENEGADO
console.log(
  "IoT 5 (Estudiante intenta eliminar_usuarios sobre IoT):",
  iotSim.ejecutarOperacionIoT({
    deviceId: "IOT-SENS-01",
    operacion: "eliminar_usuarios",
    solicitante: {
      id: "USR-002",
      rol: "Estudiante",
      departamento: "Computación",
      activa: true,
    },
    accessEngine: hibrido,
    fechaHora: "2026-11-19T11:00:00.000Z",
    contexto: { dispositivoConfiable: true },
  })
);

console.log("Eventos IoT ejecutados:", iotSim.telemetryLog.length);

const aclEngine = new NetworkAclEngine();

console.log("--- 9. Segmentación de red y ACL ---");

// 1. Tráfico permitido de VLAN 30 a sensor en VLAN 40 (192.168.0.101)
console.log(
  "ACL 1 (Permitido VLAN 30 -> VLAN 40 sensor):",
  aclEngine.evaluarTrafico({
    origenSegmento: "VLAN 30",
    ipOrigen: "192.168.30.15",
    destinoSegmento: "VLAN 40",
    ipDestino: "192.168.0.101",
    operacion: "consultar_recursos",
    solicitante: { id: "USR-002", rol: "Estudiante", departamento: "Computación", activa: true },
    recurso: { id: "IOT-SENS-01", departamento: "Computación", restringido: false },
    contexto: { dispositivoConfiable: true },
    accessEngine: hibrido,
  })
);

// 2. Tráfico bloqueado de VLAN 30 a segmento restringido VLAN 50 (192.168.50.10)
console.log(
  "ACL 2 (Denegado VLAN 30 -> VLAN 50 restringido):",
  aclEngine.evaluarTrafico({
    origenSegmento: "VLAN 30",
    ipOrigen: "192.168.30.15",
    destinoSegmento: "VLAN 50",
    ipDestino: "192.168.50.10",
    operacion: "consultar_recursos",
    solicitante: { id: "USR-002", rol: "Estudiante", departamento: "Computación", activa: true },
    recurso: { id: "SRV-ADMIN-99", restringido: true },
    contexto: { dispositivoConfiable: true },
    accessEngine: hibrido,
  })
);

// 3. Tráfico bloqueado hacia controlador restringido (192.168.0.102) desde dispositivo no confiable
console.log(
  "ACL 3 (Denegado dispositivo no confiable -> controlador restringido):",
  aclEngine.evaluarTrafico({
    origenSegmento: "VLAN 30",
    ipOrigen: "192.168.30.25",
    destinoSegmento: "VLAN 50",
    ipDestino: "192.168.0.102",
    operacion: "consultar_recursos",
    solicitante: { id: "USR-003", rol: "Técnico", departamento: "Sistemas", activa: true },
    recurso: { id: "IOT-CTRL-02", departamento: "Sistemas", restringido: true },
    contexto: { dispositivoConfiable: false },
    accessEngine: hibrido,
  })
);

console.log("Pruebas ACL registradas:", aclEngine.aclLog.length);

const auditMod = new AuditModule({
  policyEngine: hibrido,
  authModule: authMod,
  iotSimulator: iotSim,
  aclEngine,
});

console.log("--- 7.9 / 10. Módulo de auditoría: 1 prueba por cada uno de los 8 eventos ---");

// 1. Inicio de sesión
const ev1InicioSesion = auditMod.registrarEvento({
  fuente: "SESION",
  tipoEvento: AUDIT_EVENT_TYPES.LOGIN,
  identidad: "USR-001",
  rol: "Administrador",
  recursoAfectado: "SESION-001",
  operacion: "iniciar_sesion",
  resultado: "PERMITIDO",
  motivo: "Credenciales y segundo factor MFA validados correctamente",
});
console.log("Prueba 1 - Inicio de sesión:", ev1InicioSesion);

// 2. Cierre de sesión
const ev2CierreSesion = auditMod.registrarEvento({
  fuente: "SESION",
  tipoEvento: AUDIT_EVENT_TYPES.LOGOUT,
  identidad: "USR-001",
  rol: "Administrador",
  recursoAfectado: "SESION-001",
  operacion: "cerrar_sesion",
  resultado: "PERMITIDO",
  motivo: "Sesión finalizada por solicitud del usuario",
});
console.log("Prueba 2 - Cierre de sesión:", ev2CierreSesion);

// 3. Solicitud de acceso permitida
const ev3AccesoPermitido = auditMod.registrarEvento({
  fuente: "AUTORIZACION",
  tipoEvento: AUDIT_EVENT_TYPES.ACCESS_ALLOWED,
  identidad: "USR-002",
  rol: "Estudiante",
  recursoAfectado: "LAB-01",
  operacion: "consultar_recursos",
  resultado: "PERMITIDO",
  motivo: "Cumple rol y pertenencia al departamento Computación",
});
console.log("Prueba 3 - Solicitud de acceso permitida:", ev3AccesoPermitido);

// 4. Solicitud de acceso denegada
const ev4AccesoDenegado = auditMod.registrarEvento({
  fuente: "AUTORIZACION",
  tipoEvento: AUDIT_EVENT_TYPES.ACCESS_DENIED,
  identidad: "USR-002",
  rol: "Estudiante",
  recursoAfectado: "SRV-ADMIN-99",
  operacion: "consultar_recursos",
  resultado: "DENEGADO",
  motivo: "Sin regla de acceso para el recurso restringido (denegación por defecto)",
});
console.log("Prueba 4 - Solicitud de acceso denegada:", ev4AccesoDenegado);

// 5. Modificación de roles
const ev5ModRoles = auditMod.ejecutarOperacionAuditada({
  tipoEvento: AUDIT_EVENT_TYPES.ROLE_MODIFIED,
  solicitante: { id: "USR-001", rol: "Administrador", departamento: "Sistemas", activa: true },
  recursoId: "ROL-TECNICO",
  operacion: "administrar_roles",
  accessEngine: hibrido,
  motivoExito: "Permisos del rol Técnico actualizados por Administrador",
});
console.log("Prueba 5 - Modificación de roles:", ev5ModRoles);

// 6. Modificación de políticas
const ev6ModPoliticas = auditMod.ejecutarOperacionAuditada({
  tipoEvento: AUDIT_EVENT_TYPES.POLICY_MODIFIED,
  solicitante: { id: "USR-001", rol: "Administrador", departamento: "Sistemas", activa: true },
  recursoId: "POL-ABAC-04",
  operacion: "administrar_politicas",
  accessEngine: hibrido,
  motivoExito: "Política ABAC-04 actualizada por Administrador",
});
console.log("Prueba 6 - Modificación de políticas:", ev6ModPoliticas);

// 7. Modificación de dispositivos
const ev7ModDispositivos = auditMod.registrarEvento({
  fuente: "IOT",
  tipoEvento: AUDIT_EVENT_TYPES.DEVICE_MODIFIED,
  identidad: "USR-003",
  rol: "Técnico",
  recursoAfectado: "IOT-SENS-01",
  operacion: "modificar_recursos",
  resultado: "PERMITIDO",
  motivo: "Intervalo de muestreo actualizado dentro del horario autorizado",
});
console.log("Prueba 7 - Modificación de dispositivos:", ev7ModDispositivos);

// 8. Intento de operación administrativa no autorizada
const ev8AdminNoAutorizado = auditMod.ejecutarOperacionAuditada({
  tipoEvento: AUDIT_EVENT_TYPES.UNAUTHORIZED_ADMIN,
  solicitante: { id: "USR-002", rol: "Estudiante", departamento: "Computación", activa: true },
  recursoId: "POL-SEGURIDAD-GLOBAL",
  operacion: "administrar_politicas",
  accessEngine: hibrido,
});
console.log("Prueba 8 - Intento de operación administrativa no autorizada:", ev8AdminNoAutorizado);

// Consulta final del Auditor verificando los 8 tipos de evento
const consultaFinalAuditor = auditMod.consultarRegistros({
  solicitante: { id: "USR-005", rol: "Auditor", departamento: "Sistemas", activa: true },
  accessEngine: hibrido,
});
console.log("Total de registros auditados:", consultaFinalAuditor.total);
console.log("Resumen por tipo de evento:", auditMod.resumen());

console.log("--- Matriz completa de pruebas P01 - P15 ---");

// Motor unificado con reglas base para cubrir P01..P15 de forma consistente
const motorEscenarios = new HybridAccessEngine([
  {
    id: "POL-P01-EST-CONSULTA",
    operacion: "consultar_recursos",
    recursoId: "LAB-01",
    roles: ["Estudiante"],
    descripcion: "Estudiante consulta recurso permitido de su departamento",
    condicion: ({ solicitante, recurso, contexto }) => {
      const depto = recurso?.departamento ?? contexto?.departamentoRecurso;
      if (solicitante.departamento !== depto) {
        return { cumple: false, motivo: "Departamento distinto al del recurso" };
      }
      return { cumple: true };
    },
  },
  {
    id: "POL-P03-TEC-EQUIPO-ASIGNADO",
    operacion: "modificar_recursos",
    recursoId: "EQ-ASIGNADO-01",
    roles: ["Técnico"],
    descripcion: "Técnico modifica equipo asignado dentro de su departamento",
    condicion: ({ solicitante, recurso, contexto }) => {
      const depto = recurso?.departamento ?? contexto?.departamentoRecurso;
      if (solicitante.departamento !== depto) {
        return { cumple: false, motivo: "Equipo pertenece a otro departamento/técnico" };
      }
      return { cumple: true };
    },
  },
  {
    id: "POL-P04-TEC-EQUIPO-AJENO",
    operacion: "modificar_recursos",
    recursoId: "EQ-AJENO-02",
    roles: ["Técnico"],
    descripcion: "Técnico intenta modificar equipo de otro departamento/asignación",
    condicion: ({ solicitante, recurso, contexto }) => {
      const depto = recurso?.departamento ?? contexto?.departamentoRecurso;
      if (solicitante.departamento !== depto) {
        return { cumple: false, motivo: "Equipo ajeno: departamento no asignado al técnico" };
      }
      return { cumple: true };
    },
  },
  {
    id: "POL-P05-AUD-CONSULTA",
    operacion: "consultar_auditoria",
    recursoId: "*",
    roles: ["Auditor", "Administrador"],
    descripcion: "Auditor consulta registros de auditoría",
  },
  {
    id: "POL-P09-IOT-OPERACION",
    operacion: "consultar_recursos",
    recursoId: "IOT-SENS-01",
    roles: ["Estudiante", "Técnico", "Profesor", "Administrador"],
    descripcion: "Dispositivo IoT consulta recurso autorizado",
  },
  {
    id: "POL-P13-HORARIO",
    operacion: "consultar_recursos",
    recursoId: "LAB-HORARIO-01",
    roles: ["Estudiante", "Técnico", "Profesor"],
    descripcion: "Acceso sujeto a ventana horaria permitida",
    condicion: ({ contexto }) => {
      const hora = contexto?.horaAcceso;
      const inicio = contexto?.horarioInicio ?? 8;
      const fin = contexto?.horarioFin ?? 18;
      if (typeof hora === "number" && (hora < inicio || hora > fin)) {
        return { cumple: false, motivo: `Fuera de horario permitido (${inicio}:00-${fin}:00)` };
      }
      return { cumple: true };
    },
  },
]);

const estP01 = { id: "USR-P01", rol: "Estudiante", departamento: "Computación", activa: true };
const tecP03 = { id: "USR-P03", rol: "Técnico", departamento: "Sistemas", activa: true };
const audP05 = { id: "USR-P05", rol: "Auditor", departamento: "Sistemas", activa: true };
const profP12 = {
  id: "USR-P12",
  rol: "Profesor",
  departamento: "Computación",
  activa: true,
  gruposResponsable: ["GRP-CC-501"],
};

const fechaLocalDiezAm = new Date(2026, 10, 19, 10, 0, 0).toISOString();

// P01: Estudiante consulta recurso permitido -> Permitido
const rP01 = motorEscenarios.evaluate({
  solicitante: estP01,
  recurso: { id: "LAB-01", departamento: "Computación", restringido: false },
  operacion: "consultar_recursos",
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P02: Estudiante modifica políticas -> Denegado
const rP02 = motorEscenarios.evaluate({
  solicitante: estP01,
  recurso: { id: "POL-GLOBAL", departamento: "Sistemas", restringido: true },
  operacion: "modificar_politicas",
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P03: Técnico modifica equipo asignado -> Permitido
const rP03 = motorEscenarios.evaluate({
  solicitante: tecP03,
  recurso: { id: "EQ-ASIGNADO-01", departamento: "Sistemas", restringido: false },
  operacion: "modificar_recursos",
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P04: Técnico modifica equipo ajeno -> Denegado
const rP04 = motorEscenarios.evaluate({
  solicitante: tecP03,
  recurso: { id: "EQ-AJENO-02", departamento: "Redes", restringido: false },
  operacion: "modificar_recursos",
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P05: Auditor consulta registros -> Permitido
const rP05 = motorEscenarios.evaluate({
  solicitante: audP05,
  recurso: { id: "LOG-AUDITORIA", departamento: "Sistemas", restringido: true },
  operacion: "consultar_auditoria",
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P06: Auditor elimina registros -> Denegado
const rP06 = motorEscenarios.evaluate({
  solicitante: audP05,
  recurso: { id: "LOG-AUDITORIA", departamento: "Sistemas", restringido: true },
  operacion: "eliminar_registros",
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P07: Usuario deshabilitado solicita acceso -> Denegado
const rP07 = motorEscenarios.evaluate({
  solicitante: { ...estP01, activa: false },
  recurso: { id: "LAB-01", departamento: "Computación", restringido: false },
  operacion: "consultar_recursos",
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P08: Estudiante accede a VLAN administrativa -> Denegado
const rP08 = aclEngine.evaluarTrafico({
  origenSegmento: "VLAN 30",
  ipOrigen: "192.168.30.15",
  destinoSegmento: "VLAN 10",
  ipDestino: "192.168.10.5",
  operacion: "consultar_recursos",
  solicitante: estP01,
  recurso: { id: "ADMIN-CONSOLE", restringido: true },
  contexto: { dispositivoConfiable: true },
  accessEngine: motorEscenarios,
});

// P09: Dispositivo IoT realiza operación autorizada -> Permitido
const rP09 = iotSim.ejecutarOperacionIoT({
  deviceId: "IOT-SENS-01",
  operacion: "consultar_recursos",
  solicitante: estP01,
  accessEngine: motorEscenarios,
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P10: Dispositivo IoT intenta acceder a administración -> Denegado
const rP10 = iotSim.ejecutarOperacionIoT({
  deviceId: "IOT-SENS-01",
  operacion: "administrar_dispositivos",
  solicitante: estP01,
  accessEngine: motorEscenarios,
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P11: Usuario sin sesión solicita un recurso protegido -> Denegado
const rP11 = authMod.authorizeWithSession(null, motorEscenarios, {
  recurso: { id: "LOG-AUDITORIA", restringido: true },
  operacion: "consultar_auditoria",
});

// P12: Profesor accede a recurso de otro grupo -> Según política ReBAC (Denegado)
const rP12 = hibrido.evaluate({
  solicitante: profP12,
  recurso: { id: "MAT-502", grupoAcademico: "GRP-CC-502", restringido: false },
  operacion: "modificar_recursos",
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

// P13: Usuario accede fuera del horario permitido -> Denegado
const rP13 = motorEscenarios.evaluate({
  solicitante: estP01,
  recurso: { id: "LAB-HORARIO-01", departamento: "Computación", restringido: false },
  operacion: "consultar_recursos",
  fechaHora: new Date(2026, 10, 19, 23, 0, 0).toISOString(),
  contexto: { horaAcceso: 23, horarioInicio: 8, horarioFin: 18, dispositivoConfiable: true },
});

// P14: Usuario intenta escalar privilegios -> Denegado
const rP14Escala = modulo.asignarRol(
  { id: estudiante.id, rol: "Estudiante", departamento: "Computación", activa: true },
  estudiante.id,
  "Administrador"
);
const escalamientoBloqueado = rP14Escala.ok === false || rP14Escala.permitido === false;
const rP14 = {
  resultado: escalamientoBloqueado ? "DENEGADO" : "PERMITIDO",
  motivo: rP14Escala.motivo || rP14Escala.mensaje || "Intento de escalamiento de privilegios bloqueado",
};

// P15: Usuario consulta un recurso inexistente -> Denegado
const rP15 = iotSim.ejecutarOperacionIoT({
  deviceId: "IOT-INEXISTENTE-999",
  operacion: "consultar_recursos",
  solicitante: estP01,
  accessEngine: motorEscenarios,
  fechaHora: fechaLocalDiezAm,
  contexto: { dispositivoConfiable: true },
});

const matrizResultados = [
  { ID: "P01", Esperado: "Permitido", Obtenido: rP01.resultado, Motivo: rP01.motivo },
  { ID: "P02", Esperado: "Denegado", Obtenido: rP02.resultado, Motivo: rP02.motivo },
  { ID: "P03", Esperado: "Permitido", Obtenido: rP03.resultado, Motivo: rP03.motivo },
  { ID: "P04", Esperado: "Denegado", Obtenido: rP04.resultado, Motivo: rP04.motivo },
  { ID: "P05", Esperado: "Permitido", Obtenido: rP05.resultado, Motivo: rP05.motivo },
  { ID: "P06", Esperado: "Denegado", Obtenido: rP06.resultado, Motivo: rP06.motivo },
  { ID: "P07", Esperado: "Denegado", Obtenido: rP07.resultado, Motivo: rP07.motivo },
  { ID: "P08", Esperado: "Denegado", Obtenido: rP08.resultado, Motivo: rP08.motivo },
  { ID: "P09", Esperado: "Permitido", Obtenido: rP09.decision.resultado, Motivo: rP09.decision.motivo },
  { ID: "P10", Esperado: "Denegado", Obtenido: rP10.decision.resultado, Motivo: rP10.decision.motivo },
  { ID: "P11", Esperado: "Denegado", Obtenido: rP11.resultado, Motivo: rP11.motivo },
  { ID: "P12", Esperado: "Denegado (ReBAC)", Obtenido: rP12.resultado, Motivo: rP12.motivo },
  { ID: "P13", Esperado: "Denegado", Obtenido: rP13.resultado, Motivo: rP13.motivo },
  { ID: "P14", Esperado: "Denegado", Obtenido: rP14.resultado, Motivo: rP14.motivo },
  { ID: "P15", Esperado: "Denegado", Obtenido: rP15.decision.resultado, Motivo: rP15.decision.motivo },
];

console.table(matrizResultados);

const normalizarEsperado = (esp) => (esp.startsWith("Permitido") ? "PERMITIDO" : "DENEGADO");
const hayFallas = matrizResultados.some(
  (fila) => normalizarEsperado(fila.Esperado) !== String(fila.Obtenido).toUpperCase()
);

if (hayFallas) {
  console.error("Error: uno o más escenarios de la matriz P01-P15 no coincidieron con el resultado esperado.");
  process.exit(1);
}
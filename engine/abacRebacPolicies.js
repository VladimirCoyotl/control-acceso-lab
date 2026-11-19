import { PolicyEngine } from "./policyEngine.js";

// 4 Políticas ABAC (atributos y contexto)[cite: 4, 5]
export const ABAC_POLICIES = [
  {
    id: "ABAC-01-DEPTO-ESTUDIANTE",
    tipo: "ABAC",
    operacion: "consultar_recursos",
    recursoId: "*",
    roles: ["Estudiante"],
    descripcion: "Un estudiante solo puede acceder a recursos de su departamento",
    condicion: ({ solicitante, recurso, contexto }) => {
      const deptoRecurso =
        typeof recurso === "object" ? recurso?.departamento : contexto?.departamentoRecurso;
      if (!deptoRecurso || solicitante.departamento !== deptoRecurso) {
        return {
          cumple: false,
          motivo: `ABAC denegado: departamento '${solicitante.departamento}' no coincide con recurso '${deptoRecurso}'`,
        };
      }
      return { cumple: true };
    },
  },
  {
    id: "ABAC-02-HORARIO-TECNICO",
    tipo: "ABAC",
    operacion: "modificar_recursos",
    recursoId: "*",
    roles: ["Técnico"],
    descripcion: "Un técnico puede modificar equipos únicamente dentro de su horario autorizado",
    condicion: ({ fechaHora, contexto }) => {
      const horaActual =
        contexto?.horaAcceso ?? new Date(fechaHora || Date.now()).getHours();
      const inicio = contexto?.horarioInicio ?? 8;
      const fin = contexto?.horarioFin ?? 18;
      if (horaActual < inicio || horaActual >= fin) {
        return {
          cumple: false,
          motivo: `ABAC denegado: hora ${horaActual} fuera del horario autorizado (${inicio}:00-${fin}:00)`,
        };
      }
      return { cumple: true };
    },
  },
  {
    id: "ABAC-03-CUENTA-HABILITADA",
    tipo: "ABAC",
    operacion: "*",
    recursoId: "*",
    roles: ["Administrador", "Profesor", "Técnico", "Estudiante", "Auditor"],
    descripcion: "Un usuario no puede acceder a un recurso si su cuenta está deshabilitada",
    condicion: ({ solicitante }) => {
      if (!solicitante || solicitante.activa !== true) {
        return {
          cumple: false,
          motivo: "ABAC denegado: la cuenta del usuario se encuentra deshabilitada",
        };
      }
      return { cumple: true };
    },
  },
  {
    id: "ABAC-04-DISPOSITIVO-CONFIABLE",
    tipo: "ABAC",
    operacion: "*",
    recursoId: "*",
    roles: ["Administrador", "Profesor", "Técnico", "Estudiante", "Auditor"],
    descripcion:
      "Un dispositivo marcado como no confiable no puede realizar operaciones sobre recursos restringidos",
    condicion: ({ recurso, contexto }) => {
      const esRestringido =
        Boolean(recurso?.restringido) ||
        recurso?.clasificacion === "restringido" ||
        contexto?.recursoRestringido === true;
      const confiable = contexto?.dispositivoConfiable !== false;

      if (esRestringido && !confiable) {
        return {
          cumple: false,
          motivo: "ABAC denegado: dispositivo no confiable sobre recurso restringido",
        };
      }
      return { cumple: true };
    },
  },
];

// 1 Regla ReBAC (relación usuario - grupo académico / recurso)[cite: 5]
export const REBAC_POLICIES = [
  {
    id: "ReBAC-01-GRUPO-PROFESOR",
    tipo: "ReBAC",
    operacion: "modificar_recursos",
    recursoId: "*",
    roles: ["Profesor"],
    descripcion:
      "Un profesor puede administrar/modificar recursos de los grupos académicos de los que es responsable",
    condicion: ({ solicitante, recurso, contexto }) => {
      const gruposResponsable = solicitante?.gruposResponsable || [];
      const grupoRecurso =
        typeof recurso === "object" ? recurso?.grupoAcademico : contexto?.grupoAcademico;

      if (!grupoRecurso || !gruposResponsable.includes(grupoRecurso)) {
        return {
          cumple: false,
          motivo: `ReBAC denegado: el profesor no es responsable del grupo '${grupoRecurso}'`,
        };
      }
      return { cumple: true };
    },
  },
];

// Combinación RBAC + ABAC + ReBAC[cite: 5]
export class HybridAccessEngine extends PolicyEngine {
  constructor(extraPolicies = [], rolePermissions) {
    super([...ABAC_POLICIES, ...REBAC_POLICIES, ...extraPolicies], rolePermissions);
  }
}
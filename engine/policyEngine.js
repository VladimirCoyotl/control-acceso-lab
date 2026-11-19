import { ROLES } from "./identities.js";

const DEFAULT_ROLE_PERMISSIONS = {
  Administrador: [
    "consultar_usuarios",
    "crear_usuarios",
    "modificar_usuarios",
    "eliminar_usuarios",
    "consultar_recursos",
    "modificar_recursos",
    "autorizar_solicitudes",
    "consultar_auditoria",
    "modificar_politicas",
    "administrar_dispositivos",
  ],
  Profesor: ["consultar_recursos", "modificar_recursos"],
  Técnico: ["consultar_recursos", "modificar_recursos", "administrar_dispositivos"],
  Estudiante: ["consultar_recursos"],
  Auditor: ["consultar_auditoria", "consultar_recursos"],
};

export class PolicyEngine {
  constructor(policies = [], rolePermissions = DEFAULT_ROLE_PERMISSIONS) {
    this.policies = policies;
    this.rolePermissions = rolePermissions;
    this.decisionsLog = [];
  }

  registrarPolitica(policy) {
    this.policies.push(policy);
  }

  // Evalúa una solicitud con: identidad, recurso, operación, fechaHora y contexto
  evaluate(request) {
    const {
      solicitante,
      recurso,
      operacion,
      fechaHora = new Date().toISOString(),
      contexto = {},
    } = request;

    const idRecurso = typeof recurso === "string" ? recurso : recurso?.id;
    const direccionRecurso =
      typeof recurso === "object" ? recurso?.direccion ?? recurso?.ip ?? null : contexto.direccionRecurso ?? null;

    const registrarYResponder = (resultado, reglaId, motivo) => {
      const registro = {
        timestamp: fechaHora,
        solicitanteId: solicitante?.id ?? "DESCONOCIDO",
        rol: solicitante?.rol ?? "SIN_ROL",
        recursoId: idRecurso ?? "SIN_RECURSO",
        direccionRecurso,
        operacion,
        resultado,
        reglaId,
        motivo,
      };
      this.decisionsLog.push(registro);
      return {
        resultado, // "PERMITIDO" | "DENEGADO"
        reglaId,
        motivo,
        registro,
      };
    };

    // Comportamiento 5: Evitar que un usuario deshabilitado acceda a recursos
    if (!solicitante || solicitante.activa !== true) {
      return registrarYResponder(
        "DENEGADO",
        "REG-05-CUENTA-INACTIVA",
        "Usuario inexistente o cuenta deshabilitada"
      );
    }

    // Comportamiento 2: Verificar el rol del usuario
    if (!ROLES.includes(solicitante.rol)) {
      return registrarYResponder(
        "DENEGADO",
        "REG-02-ROL-INVALIDO",
        `El rol '${solicitante.rol}' no es válido`
      );
    }

    // Comportamiento 3: Verificar el permiso requerido para la operación
    const permisosRol = this.rolePermissions[solicitante.rol] || [];
    if (!permisosRol.includes(operacion)) {
      return registrarYResponder(
        "DENEGADO",
        "REG-03-PERMISO-ROL",
        `El rol '${solicitante.rol}' no tiene permiso para '${operacion}' (conocer el ID o dirección del recurso no otorga acceso)`
      );
    }

    // Buscar regla de autorización aplicable a la operación y recurso
    const reglaAplicable = this.policies.find((pol) => {
      const coincideOperacion = !pol.operacion || pol.operacion === operacion;
      const coincideRecurso =
        !pol.recursoId ||
        pol.recursoId === "*" ||
        pol.recursoId === idRecurso;
      const coincideRol = !pol.roles || pol.roles.includes(solicitante.rol);
      return coincideOperacion && coincideRecurso && coincideRol;
    });

    // Comportamiento 1: Denegar por defecto las solicitudes sin regla de autorización
    if (!reglaAplicable) {
      return registrarYResponder(
        "DENEGADO",
        "REG-01-DENEGAR-POR-DEFECTO",
        `Denegado por defecto: no existe regla de autorización para '${operacion}' sobre recurso '${idRecurso}'`
      );
    }

    // Comportamiento 4: Evaluar las condiciones adicionales configuradas
    if (typeof reglaAplicable.condicion === "function") {
      const evalCondicion = reglaAplicable.condicion({
        solicitante,
        recurso,
        operacion,
        fechaHora,
        contexto,
      });
      if (!evalCondicion.cumple) {
        return registrarYResponder(
          "DENEGADO",
          reglaAplicable.id,
          evalCondicion.motivo || `Condición no cumplida en regla ${reglaAplicable.id}`
        );
      }
    }

    // Comportamiento 6: Registrar decisión PERMITIDO
    return registrarYResponder(
      "PERMITIDO",
      reglaAplicable.id,
      reglaAplicable.descripcion || `Autorizado por regla ${reglaAplicable.id}`
    );
  }

  obtenerHistorialDecisiones() {
    return this.decisionsLog;
  }
}
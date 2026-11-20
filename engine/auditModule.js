export const AUDIT_EVENT_TYPES = {
  LOGIN: "INICIO_SESION",
  LOGOUT: "CIERRE_SESION",
  ACCESS_ALLOWED: "SOLICITUD_ACCESO_PERMITIDA",
  ACCESS_DENIED: "SOLICITUD_ACCESO_DENEGADA",
  ROLE_MODIFIED: "MODIFICACION_ROLES",
  POLICY_MODIFIED: "MODIFICACION_POLITICAS",
  DEVICE_MODIFIED: "MODIFICACION_DISPOSITIVOS",
  UNAUTHORIZED_ADMIN: "INTENTO_OPERACION_ADMIN_NO_AUTORIZADA",
};

export class AuditModule {
  constructor(options = {}) {
    this.policyEngine = options.policyEngine || null;
    this.authModule = options.authModule || null;
    this.iotSimulator = options.iotSimulator || null;
    this.aclEngine = options.aclEngine || null;
    this.extraLogs = [];
    this.contadorEventos = 0;
  }

  _siguienteId() {
    this.contadorEventos += 1;
    return `AUD-${String(this.contadorEventos).padStart(4, "0")}`;
  }

  _normalizarRegistro({
    idEvento = null,
    timestamp = null,
    identidad = "DESCONOCIDO",
    recursoAfectado = "SIN_RECURSO",
    operacion = "N/A",
    resultado = "REGISTRADO",
    motivo = "",
    tipoEvento = "EVENTO_GENERAL",
    fuente = "AUDITORIA",
    rol = "SIN_ROL",
    direccion = null,
    reglaId = "AUD-00",
  }) {
    return {
      idEvento: idEvento || this._siguienteId(),
      timestamp: timestamp || new Date().toISOString(),
      identidad,
      recursoAfectado,
      operacion,
      resultado,
      motivo,
      tipoEvento,
      fuente,
      rol,
      direccion,
      reglaId,
    };
  }

  registrarEvento(evento) {
    const entrada = this._normalizarRegistro({
      idEvento: evento.idEvento,
      timestamp: evento.timestamp,
      identidad: evento.identidad || evento.actorId || evento.solicitanteId || "DESCONOCIDO",
      recursoAfectado: evento.recursoAfectado || evento.recursoId || evento.deviceId || "SIN_RECURSO",
      operacion: evento.operacion || "N/A",
      resultado: evento.resultado || "REGISTRADO",
      motivo: evento.motivo || "",
      tipoEvento: evento.tipoEvento || evento.categoria || "EVENTO_GENERAL",
      fuente: evento.fuente || "AUDITORIA",
      rol: evento.rol || "SIN_ROL",
      direccion: evento.direccion || evento.direccionRecurso || evento.ipDestino || null,
      reglaId: evento.reglaId || "AUD-00",
    });
    this.extraLogs.push(entrada);
    return entrada;
  }

  ejecutarOperacionAuditada({
    tipoEvento,
    solicitante,
    recursoId,
    operacion,
    accessEngine = null,
    contexto = {},
    accionCallback = null,
    motivoExito = "Operación ejecutada y auditada",
  }) {
    const rol = solicitante?.rol || "SIN_ROL";
    const identidad = solicitante?.id || "DESCONOCIDO";

    if (!solicitante || solicitante.activa !== true) {
      return this.registrarEvento({
        fuente: "AUDITORIA_ADMIN",
        tipoEvento: AUDIT_EVENT_TYPES.UNAUTHORIZED_ADMIN,
        identidad,
        rol,
        recursoAfectado: recursoId,
        operacion,
        resultado: "DENEGADO",
        reglaId: "AUD-01-CUENTA-INACTIVA",
        motivo: "Intento de operación administrativa no autorizada: solicitante inactivo o inexistente",
      });
    }

    if (accessEngine) {
      const decision = accessEngine.evaluate({
        solicitante,
        recurso: { id: recursoId, departamento: contexto.departamento || "Sistemas", restringido: true },
        operacion,
        contexto: { dispositivoConfiable: true, ...contexto },
      });

      if (decision.resultado !== "PERMITIDO") {
        return this.registrarEvento({
          fuente: "AUDITORIA_ADMIN",
          tipoEvento: AUDIT_EVENT_TYPES.UNAUTHORIZED_ADMIN,
          identidad,
          rol,
          recursoAfectado: recursoId,
          operacion,
          resultado: "DENEGADO",
          reglaId: decision.reglaId,
          motivo: `Intento de operación administrativa no autorizada: ${decision.motivo}`,
        });
      }
    }

    if (typeof accionCallback === "function") {
      accionCallback();
    }

    return this.registrarEvento({
      fuente: "AUDITORIA_ADMIN",
      tipoEvento,
      identidad,
      rol,
      recursoAfectado: recursoId,
      operacion,
      resultado: "PERMITIDO",
      reglaId: "AUD-OK",
      motivo: motivoExito,
    });
  }

  recolectarRegistros() {
    let seq = 1;
    const nextFallbackId = (prefijo) => `${prefijo}-${String(seq++).padStart(4, "0")}`;
    const unificados = [];

    if (this.policyEngine?.decisionsLog) {
      for (const d of this.policyEngine.decisionsLog) {
        unificados.push(
          this._normalizarRegistro({
            idEvento: nextFallbackId("POL"),
            timestamp: d.timestamp,
            identidad: d.solicitanteId,
            recursoAfectado: d.recursoId,
            operacion: d.operacion,
            resultado: d.resultado,
            motivo: d.motivo,
            tipoEvento:
              d.resultado === "PERMITIDO"
                ? AUDIT_EVENT_TYPES.ACCESS_ALLOWED
                : AUDIT_EVENT_TYPES.ACCESS_DENIED,
            fuente: "AUTORIZACION",
            rol: d.rol,
            direccion: d.direccionRecurso ?? null,
            reglaId: d.reglaId,
          })
        );
      }
    }

    if (this.authModule?.authEvents) {
      for (const e of this.authModule.authEvents) {
        unificados.push(
          this._normalizarRegistro({
            idEvento: nextFallbackId("AUTH"),
            timestamp: e.timestamp,
            identidad: e.userId || "DESCONOCIDO",
            recursoAfectado: e.challengeId || "SESION_AUTH",
            operacion: e.type,
            resultado: e.type === "AUTH_SUCCESS" ? "PERMITIDO" : e.type,
            motivo: e.reason || (e.factorsUsed ? `Factores: ${e.factorsUsed.join(", ")}` : ""),
            tipoEvento: e.type === "AUTH_SUCCESS" ? AUDIT_EVENT_TYPES.LOGIN : e.type,
            fuente: "AUTENTICACION",
            rol: e.rol || "N/A",
            reglaId: e.type,
          })
        );
      }
    }

    if (this.iotSimulator?.telemetryLog) {
      for (const t of this.iotSimulator.telemetryLog) {
        const esModificacion =
          t.operacion === "modificar_recursos" || t.operacion === "administrar_dispositivos";
        unificados.push(
          this._normalizarRegistro({
            idEvento: nextFallbackId("IOT"),
            timestamp: t.timestamp,
            identidad: t.actorId,
            recursoAfectado: t.deviceId,
            operacion: t.operacion,
            resultado: "PERMITIDO",
            motivo: JSON.stringify(t.efecto),
            tipoEvento: esModificacion
              ? AUDIT_EVENT_TYPES.DEVICE_MODIFIED
              : AUDIT_EVENT_TYPES.ACCESS_ALLOWED,
            fuente: "IOT",
            rol: "N/A",
            direccion: t.direccion ?? null,
            reglaId: t.reglaId,
          })
        );
      }
    }

    if (this.aclEngine?.aclLog) {
      for (const a of this.aclEngine.aclLog) {
        unificados.push(
          this._normalizarRegistro({
            idEvento: nextFallbackId("ACL"),
            timestamp: new Date().toISOString(),
            identidad: "RED",
            recursoAfectado: a.ipDestino || "DESTINO_RED",
            operacion: `${a.origenSegmento || "?"} -> ${a.destinoSegmento || "?"}`,
            resultado: a.resultado,
            motivo: a.motivo,
            tipoEvento:
              a.resultado === "PERMITIDO"
                ? AUDIT_EVENT_TYPES.ACCESS_ALLOWED
                : AUDIT_EVENT_TYPES.ACCESS_DENIED,
            fuente: "RED_ACL",
            rol: "N/A",
            direccion: a.ipDestino ?? null,
            reglaId: a.reglaId,
          })
        );
      }
    }

    for (const x of this.extraLogs) {
      unificados.push(this._normalizarRegistro(x));
    }

    return unificados;
  }

  consultarRegistros({ solicitante, accessEngine, filtros = {} }) {
    if (!solicitante || solicitante.activa !== true) {
      return {
        autorizado: false,
        resultado: "DENEGADO",
        reglaId: "AUD-01-SOLICITANTE-INVALIDO",
        motivo: "Consulta de auditoría denegada: solicitante inexistente o inactivo",
        registros: [],
      };
    }

    if (accessEngine) {
      const decision = accessEngine.evaluate({
        solicitante,
        recurso: { id: "LOG-AUDITORIA-CENTRAL", departamento: "Sistemas", restringido: true },
        operacion: "consultar_auditoria",
        contexto: { dispositivoConfiable: true },
      });

      if (decision.resultado !== "PERMITIDO") {
        return {
          autorizado: false,
          resultado: "DENEGADO",
          reglaId: decision.reglaId,
          motivo: decision.motivo,
          registros: [],
        };
      }
    }

    let registros = this.recolectarRegistros();

    if (filtros.fuente) {
      registros = registros.filter((r) => r.fuente === filtros.fuente);
    }
    if (filtros.tipoEvento) {
      registros = registros.filter((r) => r.tipoEvento === filtros.tipoEvento);
    }
    if (filtros.resultado) {
      registros = registros.filter((r) => r.resultado === filtros.resultado);
    }
    if (filtros.identidad) {
      registros = registros.filter((r) => r.identidad === filtros.identidad);
    }
    if (filtros.recursoAfectado) {
      registros = registros.filter((r) => r.recursoAfectado === filtros.recursoAfectado);
    }

    return {
      autorizado: true,
      resultado: "PERMITIDO",
      total: registros.length,
      registros,
    };
  }

  resumen() {
    const todos = this.recolectarRegistros();
    const porTipoEvento = todos.reduce((acc, r) => {
      acc[r.tipoEvento] = (acc[r.tipoEvento] || 0) + 1;
      return acc;
    }, {});
    const porResultado = todos.reduce((acc, r) => {
      acc[r.resultado] = (acc[r.resultado] || 0) + 1;
      return acc;
    }, {});

    return {
      totalRegistros: todos.length,
      porTipoEvento,
      porResultado,
    };
  }
}
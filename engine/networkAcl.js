export const NETWORK_SEGMENTS = {
  ADMIN: { id: "VLAN 10", subnet: "192.168.10.0/24", descripcion: "Gestión y administración" },
  ACADEMICO: { id: "VLAN 30", subnet: "192.168.30.0/24", descripcion: "Laboratorios y red académica" },
  IOT: { id: "VLAN 40", subnet: "192.168.0.0/24", descripcion: "Sensores y cámaras IoT" },
  RESTRINGIDO: { id: "VLAN 50", subnet: "192.168.50.0/24", descripcion: "Recursos y controladores críticos" },
};

export const DEFAULT_ACL_RULES = [
  {
    id: "ACL-10-PERMIT-ACADEMICO-IOT",
    origenSegmento: "VLAN 30",
    destinoSegmento: "VLAN 40",
    operacionesPermitidas: ["consultar_recursos"],
    rolesPermitidos: ["Estudiante", "Profesor", "Técnico", "Administrador", "Auditor"],
    requiereDispositivoConfiable: true,
    accion: "PERMIT",
    motivo: "Tráfico permitido desde VLAN 30 hacia VLAN 40 para consulta",
  },
  {
    id: "ACL-20-DENY-ESTUDIANTE-RESTRINGIDO",
    origenSegmento: "VLAN 30",
    destinoSegmento: "VLAN 50",
    operacionesPermitidas: ["*"],
    rolesPermitidos: ["Estudiante"],
    accion: "DENY",
    motivo: "ACL denegado: VLAN 30 no puede acceder al segmento restringido VLAN 50",
  },
  {
    id: "ACL-30-DENY-NO-CONFIABLE-RESTRINGIDO",
    origenSegmento: "*",
    destinoSegmento: "VLAN 50",
    operacionesPermitidas: ["*"],
    rolesPermitidos: ["*"],
    requiereDispositivoConfiable: true,
    accion: "DENY",
    motivo: "ACL denegado: dispositivo no confiable hacia segmento restringido",
  },
  {
    id: "ACL-40-PERMIT-ADMIN-TECNICO",
    origenSegmento: "VLAN 10",
    destinoSegmento: "*",
    operacionesPermitidas: ["consultar_recursos", "modificar_recursos", "administrar_dispositivos", "consultar_auditoria"],
    rolesPermitidos: ["Administrador", "Técnico", "Auditor"],
    requiereDispositivoConfiable: true,
    accion: "PERMIT",
    motivo: "Tráfico de gestión autorizado desde VLAN 10",
  },
  {
    id: "ACL-99-DENY-DEFAULT",
    origenSegmento: "*",
    destinoSegmento: "*",
    operacionesPermitidas: ["*"],
    rolesPermitidos: ["*"],
    accion: "DENY",
    motivo: "ACL denegado por defecto: tráfico no autorizado entre segmentos",
  },
];

export class NetworkAclEngine {
  constructor(rules = DEFAULT_ACL_RULES) {
    this.rules = rules;
    this.aclLog = [];
  }

  evaluarTrafico({
    origenSegmento,
    ipOrigen,
    destinoSegmento,
    ipDestino,
    operacion,
    solicitante,
    recurso = {},
    contexto = {},
    accessEngine = null,
  }) {
    const dispositivoConfiable = contexto.dispositivoConfiable !== false;
    const esRestringido = recurso?.restringido === true || destinoSegmento === "VLAN 50";

    // Bloqueo explícito de dispositivo no confiable hacia recurso/segmento restringido
    if (esRestringido && !dispositivoConfiable) {
      const res = {
        comunicacion: "BLOQUEADA_ACL",
        ipOrigen,
        ipDestino,
        origenSegmento,
        destinoSegmento,
        resultado: "DENEGADO",
        reglaId: "ACL-30-DENY-NO-CONFIABLE-RESTRINGIDO",
        motivo: `ACL denegado: dispositivo no confiable (${ipOrigen}) hacia destino restringido (${ipDestino})`,
      };
      this.aclLog.push(res);
      return res;
    }

    const regla = this.rules.find((r) => {
      const matchOrigen = r.origenSegmento === "*" || r.origenSegmento === origenSegmento;
      const matchDestino = r.destinoSegmento === "*" || r.destinoSegmento === destinoSegmento;
      const matchOp =
        !r.operacionesPermitidas ||
        r.operacionesPermitidas.includes("*") ||
        r.operacionesPermitidas.includes(operacion);
      const matchRol =
        !r.rolesPermitidos ||
        r.rolesPermitidos.includes("*") ||
        (solicitante?.rol && r.rolesPermitidos.includes(solicitante.rol));
      return matchOrigen && matchDestino && matchOp && matchRol;
    });

    if (!regla || regla.accion === "DENY") {
      const res = {
        comunicacion: "BLOQUEADA_ACL",
        ipOrigen,
        ipDestino,
        origenSegmento,
        destinoSegmento,
        resultado: "DENEGADO",
        reglaId: regla?.id || "ACL-99-DENY-DEFAULT",
        motivo: regla?.motivo || "Tráfico bloqueado por ACL",
      };
      this.aclLog.push(res);
      return res;
    }

    // Si la ACL permite el tráfico de red, también validamos políticas de acceso del motor si se pasa
    if (accessEngine && solicitante) {
      const decisionMotor = accessEngine.evaluate({
        solicitante,
        recurso: { ...recurso, direccion: ipDestino },
        operacion,
        contexto: {
          ...contexto,
          origenSegmento,
          destinoSegmento,
          ipOrigen,
          ipDestino,
          direccionRecurso: ipDestino,
        },
      });

      if (decisionMotor.resultado !== "PERMITIDO") {
        const res = {
          comunicacion: "DENEGADA_POLITICA",
          ipOrigen,
          ipDestino,
          origenSegmento,
          destinoSegmento,
          aclReglaId: regla.id,
          ...decisionMotor,
        };
        this.aclLog.push(res);
        return res;
      }
    }

    const res = {
      comunicacion: "PERMITIDA",
      ipOrigen,
      ipDestino,
      origenSegmento,
      destinoSegmento,
      resultado: "PERMITIDO",
      reglaId: regla.id,
      motivo: regla.motivo,
    };
    this.aclLog.push(res);
    return res;
  }
}
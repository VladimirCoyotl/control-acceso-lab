export const IOT_DEVICES = [
  {
    id: "IOT-SENS-01",
    nombre: "Sensor Ambiental Laboratorio 01",
    tipo: "sensor",
    direccion: "192.168.0.101",
    departamento: "Computación",
    grupoAcademico: "GRP-CC-501",
    restringido: false,
    estado: "en_linea",
    lecturaActual: { temperaturaC: 22.4, humedadPct: 48 },
    parametros: { intervaloSegundos: 30 },
  },
  {
    id: "IOT-CTRL-02",
    nombre: "Controlador de Acceso Cuarto de Servidores",
    tipo: "actuador_control",
    direccion: "192.168.0.102",
    departamento: "Sistemas",
    grupoAcademico: "GRP-SIS-900",
    restringido: true,
    estado: "en_linea",
    lecturaActual: { puertaBloqueada: true, alertaIntrusión: false },
    parametros: { bloqueoEstricto: true },
  },
  {
    id: "IOT-CAM-03",
    nombre: "Cámara Perimetral Laboratorio 02",
    tipo: "camara",
    direccion: "192.168.0.103",
    departamento: "Computación",
    grupoAcademico: "GRP-CC-502",
    restringido: false,
    estado: "en_linea",
    lecturaActual: { grabando: true, movimientoDetectado: false },
    parametros: { resolucion: "1080p" },
  },
];

export class IoTSimulator {
  constructor(devices = IOT_DEVICES) {
    this.devices = new Map(devices.map((d) => [d.id, structuredClone(d)]));
    this.telemetryLog = [];
  }

  obtenerDispositivo(deviceId) {
    return this.devices.get(deviceId) || null;
  }

  listarDispositivos() {
    return Array.from(this.devices.values());
  }

  // Ejecuta una operación simulada sobre un dispositivo IoT solo si el motor autoriza
  ejecutarOperacionIoT({
    deviceId,
    operacion,
    solicitante,
    accessEngine,
    authModule = null,
    sessionToken = null,
    fechaHora = new Date().toISOString(),
    contexto = {},
    payload = {},
  }) {
    const dispositivo = this.obtenerDispositivo(deviceId);
    if (!dispositivo) {
      return {
        permitido: false,
        decision: {
          resultado: "DENEGADO",
          reglaId: "IOT-00-DISPOSITIVO-INEXISTENTE",
          motivo: `Dispositivo IoT '${deviceId}' no encontrado`,
        },
      };
    }

    const request = {
      solicitante,
      recurso: dispositivo,
      operacion,
      fechaHora,
      contexto: {
        ...contexto,
        direccionRecurso: dispositivo.direccion,
        departamentoRecurso: dispositivo.departamento,
        grupoAcademico: dispositivo.grupoAcademico,
        recursoRestringido: dispositivo.restringido,
      },
    };

    const decision = authModule
      ? authModule.authorizeWithSession(sessionToken, accessEngine, request)
      : accessEngine.evaluate(request);

    if (decision.resultado !== "PERMITIDO") {
      return {
        permitido: false,
        dispositivoId: dispositivo.id,
        direccion: dispositivo.direccion,
        decision,
      };
    }

    let efecto = null;
    if (operacion === "consultar_recursos") {
      efecto = { lectura: dispositivo.lecturaActual };
    } else if (operacion === "modificar_recursos" || operacion === "administrar_dispositivos") {
      if (payload.parametros && typeof payload.parametros === "object") {
        dispositivo.parametros = { ...dispositivo.parametros, ...payload.parametros };
      }
      if (payload.estado) {
        dispositivo.estado = payload.estado;
      }
      efecto = {
        parametrosActualizados: dispositivo.parametros,
        estado: dispositivo.estado,
      };
    }

    const evento = {
      timestamp: fechaHora,
      deviceId: dispositivo.id,
      direccion: dispositivo.direccion,
      operacion,
      actorId: solicitante?.id || decision.usuarioAutenticado?.id || "DESCONOCIDO",
      reglaId: decision.reglaId,
      efecto,
    };
    this.telemetryLog.push(evento);

    return {
      permitido: true,
      dispositivoId: dispositivo.id,
      direccion: dispositivo.direccion,
      efecto,
      decision,
    };
  }
}
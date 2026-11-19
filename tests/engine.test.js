
import { IdentityModule } from "../engine/identities.js";

const modulo = new IdentityModule();

// Usuario inicial de prueba para arrancar el ejemplo
const adminActor = {
  id: "USR-000",
  nombre: "Admin Prueba",
  rol: "Administrador",
  departamento: "Sistemas",
  activa: true,
}; //[cite: 2, 3]

// 1. Registrar usuarios (datos ficticios)[cite: 3]
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

// 2. Consultar usuarios[cite: 3]
console.log("2. Consultar:", modulo.consultarUsuarios(admin));

// 3. Modificar información[cite: 3]
console.log("3. Modificar:", modulo.modificarInformacion(admin, estudiante.id, { departamento: "Redes" }));

// 4. Activar / desactivar cuenta[cite: 3]
console.log("4. Desactivar:", modulo.cambiarEstadoCuenta(admin, estudiante.id, false));
console.log("4. Activar:", modulo.cambiarEstadoCuenta(admin, estudiante.id, true));

// 5. Asignar rol[cite: 3]
console.log("5. Asignar rol:", modulo.asignarRol(admin, estudiante.id, "Profesor"));

// 6. Consultar permisos por rol[cite: 3]
console.log("6. Permisos rol:", modulo.consultarPermisosRol("Profesor"));

// Prueba negativa: Estudiante intenta asignar rol[cite: 3]
console.log("Prueba negativa (no admin):", modulo.asignarRol(estudiante, estudiante.id, "Administrador"));


import { PolicyEngine } from "../engine/policyEngine.js";

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
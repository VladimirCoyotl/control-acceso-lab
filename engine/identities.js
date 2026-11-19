import crypto from "crypto";
const ROLES = ["Administrador", "Profesor", "Técnico", "Estudiante", "Auditor"]; //[cite: 2, 3]

const ROLE_PERMISSIONS = {
  Administrador: [
    "consultar_usuarios",
    "crear_usuarios",
    "modificar_usuarios",
    "cambiar_estado_cuenta",
    "asignar_roles",
    "consultar_permisos_rol",
  ], //[cite: 3]
  Profesor: ["consultar_usuarios", "consultar_permisos_rol"], //[cite: 3]
  Técnico: ["consultar_usuarios", "consultar_permisos_rol"], //[cite: 3]
  Estudiante: ["consultar_usuarios", "consultar_permisos_rol"], //[cite: 3]
  Auditor: ["consultar_usuarios", "consultar_permisos_rol"], //[cite: 3]
};

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function esAdmin(actor) {
  return Boolean(actor && actor.activa && actor.rol === "Administrador"); //[cite: 3]
}

class IdentityModule {
  constructor() {
    this.users = new Map();
    this.counter = 1;
  }

  // 1. Registrar usuarios[cite: 3]
  registrarUsuario(actor, { nombre, rol, departamento, password }) {
    if (!esAdmin(actor)) {
      return { ok: false, error: "Acceso denegado: solo Administrador puede registrar usuarios" }; //[cite: 3]
    }
    if (!ROLES.includes(rol)) {
      return { ok: false, error: "Rol no válido" }; //[cite: 2, 3]
    }
    const id = `USR-${String(this.counter++).padStart(3, "0")}`; //[cite: 3]
    const user = {
      id, //[cite: 3]
      nombre, //[cite: 3]
      rol, //[cite: 3]
      departamento, //[cite: 3]
      activa: true, //[cite: 3]
      fechaRegistro: new Date().toISOString(), //[cite: 3]
      passwordHash: password ? hashPassword(password) : null, //[cite: 3]
    };
    this.users.set(id, user);
    return { ok: true, usuario: this.sanitizarUsuario(user) }; //[cite: 3]
  }

  // 2. Consultar usuarios[cite: 3]
  consultarUsuarios(actor) {
    if (!actor || !actor.activa) {
      return { ok: false, error: "Usuario no autenticado o inactivo" }; //[cite: 3]
    }
    const lista = Array.from(this.users.values()).map((u) => this.sanitizarUsuario(u));
    return { ok: true, usuarios: lista };
  }

  // 3. Modificar información[cite: 3]
  modificarInformacion(actor, userId, { nombre, departamento }) {
    if (!esAdmin(actor)) {
      return { ok: false, error: "Acceso denegado: solo Administrador puede modificar identidades" }; //[cite: 3]
    }
    const user = this.users.get(userId);
    if (!user) return { ok: false, error: "Usuario no encontrado" };

    if (nombre !== undefined) user.nombre = nombre; //[cite: 3]
    if (departamento !== undefined) user.departamento = departamento; //[cite: 3]
    return { ok: true, usuario: this.sanitizarUsuario(user) };
  }

  // 4. Activar o desactivar cuentas[cite: 3]
  cambiarEstadoCuenta(actor, userId, activa) {
    if (!esAdmin(actor)) {
      return { ok: false, error: "Acceso denegado: solo Administrador puede cambiar estado" }; //[cite: 3]
    }
    const user = this.users.get(userId);
    if (!user) return { ok: false, error: "Usuario no encontrado" };

    user.activa = Boolean(activa); //[cite: 3]
    return { ok: true, usuario: this.sanitizarUsuario(user) };
  }

  // 5. Asignar roles[cite: 3]
  asignarRol(actor, userId, nuevoRol) {
    if (!esAdmin(actor)) {
      return { ok: false, error: "Acceso denegado: solo Administrador puede asignar roles" }; //[cite: 3]
    }
    if (!ROLES.includes(nuevoRol)) {
      return { ok: false, error: "Rol no válido" }; //[cite: 2, 3]
    }
    const user = this.users.get(userId);
    if (!user) return { ok: false, error: "Usuario no encontrado" };

    user.rol = nuevoRol; //[cite: 3]
    return { ok: true, usuario: this.sanitizarUsuario(user) };
  }

  // 6. Consultar los permisos asociados a cada rol[cite: 3]
  consultarPermisosRol(rol) {
    if (!ROLES.includes(rol)) {
      return { ok: false, error: "Rol no válido" }; //[cite: 2, 3]
    }
    return { ok: true, rol, permisos: ROLE_PERMISSIONS[rol] }; //[cite: 3]
  }

  sanitizarUsuario(user) {
    const { passwordHash, ...sinHash } = user;
    return sinHash; //[cite: 3]
  }
}

export { IdentityModule, ROLES, ROLE_PERMISSIONS };
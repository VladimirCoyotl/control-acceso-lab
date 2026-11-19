import crypto from "crypto";
import { ROLES } from "./identities.js";

function verifyPasswordHash(password, storedHash) {
  if (!password || !storedHash || !storedHash.includes(":")) return false;
  const [salt, originalHex] = storedHash.split(":");
  const derivedBuf = crypto.scryptSync(password, salt, 64);
  const originalBuf = Buffer.from(originalHex, "hex");
  if (derivedBuf.length !== originalBuf.length) return false;
  return crypto.timingSafeEqual(derivedBuf, originalBuf);
}

export class AuthModule {
  constructor(options = {}) {
    this.provider = options.provider || "Microsoft Entra ID (Simulación/Integración)";
    this.mfaRequiredRoles =
      options.mfaRequiredRoles || ["Administrador", "Profesor", "Técnico", "Auditor"];
    this.sessions = new Map();
    this.pendingMfa = new Map();
    this.authEvents = [];
  }

  recordEvent(type, payload) {
    const event = {
      timestamp: new Date().toISOString(),
      provider: this.provider,
      type,
      ...payload,
    };
    this.authEvents.push(event);
    return event;
  }

  // Paso 1 del flujo: validar identidad y credencial; emitir desafío MFA si aplica
  initiateAuthentication(userRecord, password) {
    if (!userRecord || userRecord.activa !== true) {
      this.recordEvent("AUTH_FAILED", {
        userId: userRecord?.id || "DESCONOCIDO",
        reason: "Usuario inexistente o cuenta deshabilitada",
      });
      return {
        authenticated: false,
        status: "DENEGADO",
        reason: "Autenticación fallida: usuario inexistente o cuenta deshabilitada",
      };
    }

    const passwordOk = verifyPasswordHash(password, userRecord.passwordHash);
    if (!passwordOk) {
      this.recordEvent("AUTH_FAILED", {
        userId: userRecord.id,
        reason: "Credencial inválida",
      });
      return {
        authenticated: false,
        status: "DENEGADO",
        reason: "Autenticación fallida: credencial inválida",
      };
    }

    const requiresMfa = this.mfaRequiredRoles.includes(userRecord.rol);
    if (requiresMfa) {
      const challengeId = `MFA-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
      const expectedCode = String(crypto.randomInt(100000, 999999));

      this.pendingMfa.set(challengeId, {
        userId: userRecord.id,
        userSnapshot: {
          id: userRecord.id,
          nombre: userRecord.nombre,
          rol: userRecord.rol,
          departamento: userRecord.departamento,
          activa: userRecord.activa,
          gruposResponsable: userRecord.gruposResponsable || [],
        },
        expectedCode,
        expiresAt: Date.now() + 5 * 60 * 1000,
      });

      this.recordEvent("MFA_CHALLENGE_ISSUED", {
        userId: userRecord.id,
        rol: userRecord.rol,
        challengeId,
      });

      return {
        authenticated: false,
        mfaRequired: true,
        status: "MFA_PENDIENTE",
        provider: this.provider,
        challengeId,
        factorsSupported: [
          "Aplicación autenticadora (TOTP / Microsoft Authenticator)",
          "Código de verificación de un solo uso (OTP)",
          "Factor adicional de prueba simulado",
        ],
        // Solo para pruebas locales en consola; nunca exponer en producción
        debugTestCode: expectedCode,
      };
    }

    return this.createSession(userRecord, ["password"]);
  }

  // Paso 2 del flujo: completar autenticación multifactor
  completeMfa(challengeId, code) {
    const challenge = this.pendingMfa.get(challengeId);
    if (!challenge) {
      this.recordEvent("MFA_FAILED", {
        challengeId,
        reason: "Desafío MFA inexistente o ya utilizado",
      });
      return {
        authenticated: false,
        status: "NO_AUTENTICADO",
        reason: "No se completó el proceso MFA: desafío inválido o expirado",
      };
    }

    if (Date.now() > challenge.expiresAt) {
      this.pendingMfa.delete(challengeId);
      this.recordEvent("MFA_EXPIRED", {
        userId: challenge.userId,
        challengeId,
      });
      return {
        authenticated: false,
        status: "NO_AUTENTICADO",
        reason: "No se completó el proceso MFA: el código expiró",
      };
    }

    if (String(code) !== challenge.expectedCode) {
      this.recordEvent("MFA_FAILED", {
        userId: challenge.userId,
        challengeId,
        reason: "Código MFA incorrecto",
      });
      return {
        authenticated: false,
        status: "NO_AUTENTICADO",
        reason: "Autenticación incompleta: código MFA incorrecto (usuario sigue sin sesión válida)",
      };
    }

    this.pendingMfa.delete(challengeId);
    return this.createSession(challenge.userSnapshot, ["password", "mfa_totp"]);
  }

  createSession(user, factorsUsed) {
    const token = `SES-${crypto.randomBytes(12).toString("hex")}`;
    const session = {
      token,
      provider: this.provider,
      user: {
        id: user.id,
        nombre: user.nombre,
        rol: user.rol,
        departamento: user.departamento,
        activa: user.activa,
        gruposResponsable: user.gruposResponsable || [],
      },
      factorsUsed,
      authenticatedAt: new Date().toISOString(),
    };
    this.sessions.set(token, session);
    this.recordEvent("AUTH_SUCCESS", {
      userId: user.id,
      rol: user.rol,
      factorsUsed,
    });
    return {
      authenticated: true,
      status: "AUTENTICADO",
      session,
    };
  }

  // Identifica al usuario autenticado a partir de su token de sesión
  getAuthenticatedUser(token) {
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session || !session.user?.activa) return null;
    if (!ROLES.includes(session.user.rol)) return null;
    return session.user;
  }

  // Separa autenticación (identidad) de autorización (evaluación en PolicyEngine)
  authorizeWithSession(token, policyEngine, request) {
    const authenticatedUser = this.getAuthenticatedUser(token);
    if (!authenticatedUser) {
      return {
        authenticated: false,
        resultado: "DENEGADO",
        reglaId: "AUTH-00-SIN-SESION",
        motivo: "Acceso denegado: usuario no autenticado o autenticación incompleta",
      };
    }

    const decision = policyEngine.evaluate({
      ...request,
      solicitante: authenticatedUser,
    });

    return {
      authenticated: true,
      usuarioAutenticado: {
        id: authenticatedUser.id,
        nombre: authenticatedUser.nombre,
        rol: authenticatedUser.rol,
      },
      ...decision,
    };
  }
}
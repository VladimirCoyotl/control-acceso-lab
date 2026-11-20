# Control de Acceso Lab

Plataforma de control de acceso para un laboratorio universitario (proyecto final de Control y Acceso de Sistemas, BUAP-FCC).
Combina **RBAC + ABAC + ReBAC**, autenticación con **MFA simulado**, **ACL de red**, **dispositivos IoT** y **auditoría**, con una interfaz web
publicada en **Azure Static Web Apps** (plan Free).

> **Aviso:** al ser una aplicación estática, las decisiones de autorización corren en el navegador y son una **simulación académica**.
> No protegen recursos reales; en producción las decisiones deben tomarse en un servidor/API y la identidad en Microsoft Entra ID.

## Estructura

```
engine/            Motor (módulos independientes)
  identities.js      Usuarios, roles y permisos por rol (RF01, RF02)
  policyEngine.js    Motor de autorización, denegar por defecto (RF04-RF06)
  abacRebacPolicies.js  4 políticas ABAC + 1 ReBAC
  authModule.js      Autenticación, sesiones y MFA simulado
  networkAcl.js      Segmentos VLAN y reglas ACL (RF10)
  iotSimulator.js    Dispositivos IoT (RF09)
  auditModule.js     Eventos de auditoría y consulta (RF07, RF08)
public/            Interfaz web (HTML/CSS/JS sin framework)
  js/crypto-shim.js  Sustituto de `crypto` de Node para el navegador (simulación)
scripts/build.js   Ejecuta pruebas y genera dist/
tests/             Pruebas y matriz P01-P15
.github/workflows/ Despliegue a Azure Static Web Apps
```

## Instalación y ejecución

Requisitos: Node.js 18 o superior. No hay dependencias que instalar.

```bash
npm test          # ejecuta las pruebas; falla si la matriz P01-P15 no coincide
npm run build     # pruebas + genera dist/ (interfaz, motor y resultados)
npx serve dist    # (opcional) abrir el sitio local en http://localhost:3000
```

## Usuarios de demostración (datos ficticios)

Contraseña de todos: `Demo#2026`. Todos los roles excepto Estudiante piden MFA; el código aparece en el "simulador de autenticador".

| ID | Nombre | Rol |
|---|---|---|
| USR-001 | Ana López | Administrador |
| USR-002 | Carlos Ruiz | Profesor (grupo GRP-CC-501) |
| USR-003 | Marta Díaz | Técnico |
| USR-004 | Luis Pérez | Estudiante |
| USR-005 | Sofía Vega | Auditor |

## Vistas de la interfaz

Panel principal · Usuarios · Recursos · Políticas · Solicitudes · Auditoría (con exportación CSV/JSON) · Red/ACL · Dispositivos IoT · Pruebas.
Las acciones administrativas se ocultan a los perfiles sin permiso **y además** las valida el motor en cada operación.

## Despliegue en Azure

Cada `push` a `main` ejecuta `.github/workflows/azure-static-web-apps-*.yml`: instala Node 20, corre `npm run build` (si falla una prueba, no se publica)
y sube `dist/` con `Azure/static-web-apps-deploy` (`skip_app_build: true`). El token de despliegue vive solo como secret del repositorio
(`AZURE_STATIC_WEB_APPS_API_TOKEN_...`); no está en el código. `public/staticwebapp.config.json` agrega cabeceras de seguridad (CSP, nosniff, X-Frame-Options).

## Qué es real, qué es simulado

| Mecanismo | Estado |
|---|---|
| RBAC / ABAC / ReBAC, denegar por defecto, auditoría, ACL | Implementado (en el navegador) |
| Autenticación y hash de contraseñas | Simulado (SHA-256 iterado con sal; en producción, Entra ID) |
| MFA | Simulado (código mostrado en pantalla; en producción, TOTP/Authenticator) |
| Persistencia | Solo en memoria; se reinicia al recargar |
| Autorización en servidor | Propuesta de mejora (Azure Functions + Entra ID) |

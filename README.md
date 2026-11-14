# Authz Lab

Laboratorio de **autorización de grano fino**. Inicias sesión en el [IAM Lab](https://lab.spliter.dev) con uno de los usuarios de una empresa ficticia, intentas administrar usuarios, roles, aplicaciones, robots y agentes de IA, y ves **por qué** te dejan o no, regla a regla.

**→ [authz.spliter.dev](https://authz.spliter.dev)**

> **Cómo está hecho:** programado en pareja con IA ([Claude Code](https://claude.com/claude-code)). Qué enseña el lab, cómo se estructura y las decisiones de seguridad son mías; abajo explico las principales.

## La idea: reglas ortogonales

En lugar de un rol para cada combinación (`aprobador-pagos-hasta-10k-con-mfa`…), cada decisión se divide en seis preguntas independientes:

| Dimensión | Pregunta |
|---|---|
| **Capacidad** | ¿Alguno de tus roles incluye la acción? |
| **Ámbito** | ¿El recurso está en tu alcance: toda la empresa, tu equipo o lo tuyo? |
| **Relación** | ¿Tienes el vínculo que exige: propietario, responsable del solicitante? |
| **Límite** | ¿Estás dentro de tus topes de nivel de privilegio y de riesgo? |
| **Contexto** | ¿La sesión cumple las condiciones: MFA, dispositivo gestionado? |
| **Prohibición** | ¿Hay algo que lo impida siempre? Gana a cualquier permiso. |

`permitido = capacidad ∧ ámbito ∧ relación ∧ límite ∧ contexto ∧ ¬prohibición`

Cada dimensión se gestiona por separado y no conoce a las demás. Toda decisión devuelve la traza completa.

## Decisiones

- **Dimensiones ortogonales en lugar de roles combinados.** Los roles que mezclan acción, alcance, límites y contexto explotan en número y nadie sabe qué conceden. Separarlos en seis preguntas permite cambiar una sin tocar las demás.
- **Las prohibiciones ganan siempre.** Separación de funciones o "ningún agente de IA con permisos críticos" no deben depender de que nadie se olvide de quitar un permiso, así que se evalúan aparte y anulan cualquier concesión.
- **Toda decisión explica su porqué.** El motor devuelve la traza de las seis dimensiones, no solo un sí o un no. Una autorización que no se puede explicar no se puede auditar.
- **Robots y agentes de IA como identidades de primera clase.** Hoy buena parte de los accesos no son de personas, y es donde más falla el control. Por eso tienen dueño, ámbito y límites como cualquier usuario.
- **Identidad delegada al IAM Lab.** La autenticación se resuelve en otro sitio (OIDC) y aquí solo se decide qué puedes hacer. Esa separación es la misma que en un sistema real, y conecta los dos labs.

## Escenario

| Usuario | Perfil |
|---|---|
| Ana Torres | Administradora de IAM (nivel 4) |
| Bruno Gil | Responsable del equipo Pagos (nivel 2) |
| Carla Ruiz | Desarrolladora en Pagos, reporta a Bruno |
| Elena Vidal | Desarrolladora en Tarjetas |
| David León | Auditor: lo ve todo, no cambia nada |
| Alex Prueba | Empleado básico, solo autoservicio |

Recursos: usuarios, roles, aplicaciones OAuth, robots (cuentas de servicio), agentes de IA y solicitudes de acceso. Algunas pruebas interesantes:

- Bruno aprueba la solicitud de Carla, pero no la suya propia (prohibición).
- Bruno no puede dar a nadie un rol de nivel superior al suyo (límite).
- Carla rota las credenciales de su robot solo si entró con MFA (contexto).
- Ni la administradora puede dar permisos de riesgo «crítico» a un agente (prohibición).

## Arquitectura

```
navegador ──► authz-lab (Worker)
               ├─ /login, /callback   OIDC + PKCE contra el IAM Lab
               ├─ /api/*              motor de reglas (src/engine.ts)
               └─ service binding ──► iam-lab (Worker): /as/token, /as/jwks
```

- **Login**: Authorization Code + PKCE, `state` y `nonce` en una cookie HttpOnly temporal.
- **Sesión**: el propio `id_token` en una cookie HttpOnly, validado (firma ES256, emisor, audiencia y caducidad) en cada petición. Sin base de datos ni secretos propios.
- **MFA**: se lee del claim `amr` del `id_token`; el dispositivo gestionado se simula con un interruptor.
- **Tráfico en vivo**: cada clic dibuja la petición real mientras ocurre (navegador → Worker → motor → respuesta), con las seis dimensiones encendiéndose según la traza que devuelve el servidor y un registro con el tiempo medido. El Worker añade la cabecera `Server-Timing: jwks;desc="cache|iam"`, así que el salto al IAM Lab solo se anima cuando de verdad se pidió la clave por el service binding. La portada reproduce casos de ejemplo decididos por el motor real (`/api/demo`). Sin dependencias ni build (Web Animations API) y respetando `prefers-reduced-motion`.
- **Motor**: TypeScript sin dependencias. Las reglas están en `src/policy.ts` y los datos en `src/model.ts`.

Todo cabe en el plan gratuito de Cloudflare Workers.

## Despliegue

1. El IAM Lab debe estar desplegado como Worker `iam-lab` en la misma cuenta (lo usa el service binding).
2. Cloudflare → Workers & Pages → Importar repositorio → este repo, nombre **`authz-lab`**.
3. Dominio personalizado: `authz.spliter.dev`.

## Tests

```bash
node --test test/*.test.ts
```

Requiere Node 22.18 o superior (ejecuta TypeScript directamente).

---

Relacionado con el [IAM Lab](https://github.com/ismaspliter/iam-lab) · Hecho por [spliter.dev](https://spliter.dev).

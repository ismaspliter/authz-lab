// Las reglas del laboratorio, separadas en dimensiones ORTOGONALES.
// Cada dimensión responde a una pregunta distinta y no sabe nada de las demás:
//
//   capacidad   ¿Alguno de tus roles incluye esta acción?
//   ámbito      ¿El recurso está dentro de tu alcance (todo, tu equipo, lo tuyo)?
//   relación    ¿Tienes el vínculo que exige la acción (propietario, responsable)?
//   límite      ¿Estás dentro de tus topes (nivel de privilegio, riesgo)?
//   contexto    ¿Las condiciones de la sesión son suficientes (MFA, dispositivo)?
//   prohibición ¿Hay alguna regla que lo impida siempre? (gana a todo lo demás)

import { RISKS, type Principal, type Resource, type Risk, roleById, principalBySub } from "./model.ts";

export type Scope = "global" | "equipo" | "propio";
export type Relation = "propietario" | "responsable_del_solicitante";

export interface Grant {
  perm: string; // "kind:accion", "kind:*" o "*:accion"
  scope: Scope;
  relation?: Relation;
}

export interface Context {
  mfa: boolean;
  managedDevice: boolean;
}

export interface AuthzRequest {
  principal: Principal;
  resource: Resource;
  action: string;
  params: { role?: string; risk?: Risk };
  context: Context;
}

export interface Check {
  ok: boolean;
  detail: string;
}

export interface Rule {
  id: string;
  text: string;
  applies: (r: AuthzRequest) => boolean;
  check: (r: AuthzRequest) => Check;
}

// ---------- capacidad: qué incluye cada rol ----------

export const ROLE_GRANTS: Record<string, Grant[]> = {
  empleado: [
    { perm: "user:ver", scope: "equipo" },
    { perm: "user:editar", scope: "propio" },
    { perm: "role:ver", scope: "global" },
    { perm: "role:solicitar", scope: "global" },
    { perm: "request:ver", scope: "propio" },
  ],
  developer: [
    { perm: "app:ver", scope: "equipo" },
    { perm: "app:editar", scope: "equipo", relation: "propietario" },
    { perm: "robot:ver", scope: "equipo" },
    { perm: "robot:rotar_credenciales", scope: "equipo", relation: "propietario" },
    { perm: "agent:ver", scope: "equipo" },
    { perm: "agent:conceder_permisos", scope: "equipo", relation: "propietario" },
    { perm: "agent:suspender", scope: "equipo", relation: "propietario" },
  ],
  team_lead: [
    { perm: "user:ver", scope: "equipo" },
    { perm: "user:editar", scope: "equipo" },
    { perm: "user:asignar_rol", scope: "equipo" },
    { perm: "request:ver", scope: "equipo" },
    { perm: "request:aprobar", scope: "equipo", relation: "responsable_del_solicitante" },
    { perm: "app:*", scope: "equipo" },
    { perm: "robot:*", scope: "equipo" },
    { perm: "agent:*", scope: "equipo" },
  ],
  auditor: [{ perm: "*:ver", scope: "global" }],
  iam_admin: [{ perm: "*:*", scope: "global" }],
};

export function matches(perm: string, kind: string, action: string): boolean {
  const [k, a] = perm.split(":");
  return (k === "*" || k === kind) && (a === "*" || a === action);
}

// ---------- ámbito ----------

export function inScope(scope: Scope, r: AuthzRequest): Check {
  const { principal: p, resource: res } = r;
  if (scope === "global") return { ok: true, detail: "Tu rol aplica a toda la empresa." };
  if (scope === "propio") {
    const mine = res.id === p.sub || res.owner === p.sub || res.requester === p.sub;
    return mine
      ? { ok: true, detail: "Es tuyo." }
      : { ok: false, detail: "Este permiso solo vale sobre lo tuyo, y este recurso no lo es." };
  }
  if (!res.team) return { ok: true, detail: "Recurso común a toda la empresa." };
  return res.team === p.team
    ? { ok: true, detail: `Es del equipo ${res.team}, el tuyo.` }
    : { ok: false, detail: `Es del equipo ${res.team} y tu alcance es el equipo ${p.team}.` };
}

// ---------- relación ----------

export function hasRelation(relation: Relation, r: AuthzRequest): Check {
  const { principal: p, resource: res } = r;
  if (relation === "propietario")
    return res.owner === p.sub
      ? { ok: true, detail: "Eres la persona propietaria." }
      : { ok: false, detail: `Hace falta ser propietario; lo es ${principalBySub(res.owner ?? "")?.name ?? "otra persona"}.` };
  const requester = principalBySub(res.requester ?? "");
  return requester?.manager === p.sub
    ? { ok: true, detail: `Eres responsable directo de ${requester.name}.` }
    : { ok: false, detail: `Solo puede aprobarla quien sea responsable directo de ${requester?.name ?? "quien la pide"}.` };
}

// ---------- límite ----------

const riskIndex = (r: Risk) => RISKS.indexOf(r);

export const LIMITS: Rule[] = [
  {
    id: "L1",
    text: "No puedes asignar un rol de nivel superior al tuyo.",
    applies: (r) => r.resource.kind === "user" && r.action === "asignar_rol",
    check: (r) => {
      const role = roleById(r.params.role ?? "");
      if (!role) return { ok: false, detail: "Rol desconocido." };
      return (role.level ?? 0) <= r.principal.level
        ? { ok: true, detail: `«${role.name}» es nivel ${role.level}; el tuyo es ${r.principal.level}.` }
        : { ok: false, detail: `«${role.name}» es nivel ${role.level} y tu nivel es ${r.principal.level}: sería escalar privilegios.` };
    },
  },
  {
    id: "L2",
    text: "No puedes aprobar acceso a un rol de nivel superior al tuyo.",
    applies: (r) => r.resource.kind === "request" && r.action === "aprobar",
    check: (r) => {
      const role = roleById(r.resource.role ?? "");
      return (role?.level ?? 0) <= r.principal.level
        ? { ok: true, detail: `El rol pedido es nivel ${role?.level}; el tuyo es ${r.principal.level}.` }
        : { ok: false, detail: `El rol pedido («${role?.name}») es nivel ${role?.level} y el tuyo es ${r.principal.level}.` };
    },
  },
  {
    id: "L3",
    text: "No puedes dar a un agente más riesgo del que tienes permitido conceder.",
    applies: (r) => r.resource.kind === "agent" && r.action === "conceder_permisos",
    check: (r) => {
      const risk = r.params.risk ?? "bajo";
      return riskIndex(risk) <= riskIndex(r.principal.maxRisk)
        ? { ok: true, detail: `Riesgo «${risk}»; puedes conceder hasta «${r.principal.maxRisk}».` }
        : { ok: false, detail: `Riesgo «${risk}» y solo puedes conceder hasta «${r.principal.maxRisk}».` };
    },
  },
];

// ---------- contexto ----------

const SENSITIVE = ["asignar_rol", "desactivar", "eliminar", "rotar_credenciales", "aprobar"];
const DESTRUCTIVE = ["desactivar", "eliminar"];

export const CONTEXT: Rule[] = [
  {
    id: "C1",
    text: "Las acciones sensibles (asignar roles, aprobar, rotar credenciales, desactivar o eliminar) exigen haber iniciado sesión con MFA.",
    applies: (r) => SENSITIVE.includes(r.action) || (r.action === "conceder_permisos" && riskIndex(r.params.risk ?? "bajo") >= 2),
    check: (r) =>
      r.context.mfa
        ? { ok: true, detail: "Tu sesión incluye segundo factor (amr contiene «mfa»)." }
        : { ok: false, detail: "Acción sensible y tu sesión no usó MFA. Vuelve a entrar marcando el segundo factor." },
  },
  {
    id: "C2",
    text: "Desactivar o eliminar solo se permite desde un dispositivo gestionado por la empresa.",
    applies: (r) => DESTRUCTIVE.includes(r.action),
    check: (r) =>
      r.context.managedDevice
        ? { ok: true, detail: "Dispositivo gestionado." }
        : { ok: false, detail: "Acción destructiva desde un dispositivo no gestionado." },
  },
];

// ---------- prohibiciones (siempre ganan) ----------

export const PROHIBITIONS: Rule[] = [
  {
    id: "P1",
    text: "Nadie puede aprobar su propia solicitud (segregación de funciones).",
    applies: (r) => r.resource.kind === "request" && r.action === "aprobar",
    check: (r) => (r.resource.requester === r.principal.sub ? { ok: false, detail: "Es tu propia solicitud." } : { ok: true, detail: "" }),
  },
  {
    id: "P2",
    text: "Nadie puede asignarse roles a sí mismo.",
    applies: (r) => r.resource.kind === "user" && r.action === "asignar_rol",
    check: (r) => (r.resource.id === r.principal.sub ? { ok: false, detail: "Intentas asignarte un rol a ti mismo." } : { ok: true, detail: "" }),
  },
  {
    id: "P3",
    text: "Un auditor nunca modifica nada: solo lectura.",
    applies: (r) => r.principal.roles.includes("auditor") && !r.principal.roles.includes("iam_admin") && r.action !== "ver",
    check: () => ({ ok: false, detail: "Tienes el rol de auditor, que es incompatible con cualquier cambio." }),
  },
  {
    id: "P4",
    text: "Ningún agente de IA puede recibir permisos de riesgo «crítico».",
    applies: (r) => r.resource.kind === "agent" && r.action === "conceder_permisos",
    check: (r) => (r.params.risk === "crítico" ? { ok: false, detail: "Los agentes no pueden tener permisos críticos, lo pida quien lo pida." } : { ok: true, detail: "" }),
  },
];

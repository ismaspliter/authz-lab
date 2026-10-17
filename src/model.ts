// Modelo y datos del laboratorio: el directorio de una empresa ficticia.
// El IAM Lab dice QUIÉN eres (sub). Este directorio dice QUÉ atributos tienes.

export type Kind = "user" | "role" | "app" | "robot" | "agent" | "request";
export type Risk = "bajo" | "medio" | "alto" | "crítico";
export const RISKS: Risk[] = ["bajo", "medio", "alto", "crítico"];

export interface Principal {
  sub: string;
  name: string;
  team: string;
  title: string;
  roles: string[];
  level: number; // nivel de privilegio: 1 básico … 4 administración total
  maxRisk: Risk; // riesgo máximo que puede conceder a un agente
  manager?: string;
}

export interface Resource {
  id: string;
  kind: Kind;
  name: string;
  team?: string;
  owner?: string; // sub del propietario (apps, robots, agentes)
  description: string;
  // específicos
  level?: number; // roles
  risk?: Risk; // agentes
  requester?: string; // solicitudes
  role?: string; // solicitudes: id del rol pedido
}

export const PRINCIPALS: Principal[] = [
  { sub: "usr_7f3a9c", name: "Alex Prueba", team: "Marketing", title: "Usuario de prueba", roles: ["empleado"], level: 1, maxRisk: "bajo" },
  { sub: "usr_ana", name: "Ana Torres", team: "Plataforma", title: "Administradora de IAM", roles: ["empleado", "iam_admin"], level: 4, maxRisk: "alto" },
  { sub: "usr_bruno", name: "Bruno Gil", team: "Pagos", title: "Responsable del equipo Pagos", roles: ["empleado", "team_lead"], level: 2, maxRisk: "alto" },
  { sub: "usr_carla", name: "Carla Ruiz", team: "Pagos", title: "Desarrolladora en Pagos", roles: ["empleado", "developer"], level: 1, maxRisk: "medio", manager: "usr_bruno" },
  { sub: "usr_elena", name: "Elena Vidal", team: "Tarjetas", title: "Desarrolladora en Tarjetas", roles: ["empleado", "developer"], level: 1, maxRisk: "medio" },
  { sub: "usr_david", name: "David León", team: "Auditoría", title: "Auditor", roles: ["empleado", "auditor"], level: 1, maxRisk: "bajo" },
];

export const ROLES: Resource[] = [
  { id: "empleado", kind: "role", name: "Empleado", level: 1, description: "Acceso básico y autoservicio." },
  { id: "developer", kind: "role", name: "Desarrollador", level: 1, description: "Gestiona las apps, robots y agentes que le pertenecen." },
  { id: "auditor", kind: "role", name: "Auditor", level: 1, description: "Lo ve todo, no cambia nada." },
  { id: "team_lead", kind: "role", name: "Responsable de equipo", level: 2, description: "Administra su equipo y aprueba sus solicitudes." },
  { id: "iam_admin", kind: "role", name: "Administrador de IAM", level: 4, description: "Administración completa de identidades." },
];

const userResources: Resource[] = PRINCIPALS.map((p) => ({
  id: p.sub,
  kind: "user",
  name: p.name,
  team: p.team,
  description: p.title,
}));

export const RESOURCES: Resource[] = [
  ...userResources,
  ...ROLES,
  { id: "app_pasarela", kind: "app", name: "Pasarela de pagos", team: "Pagos", owner: "usr_carla", description: "Aplicación OAuth registrada por el equipo Pagos." },
  { id: "app_extractos", kind: "app", name: "Extractos de tarjeta", team: "Tarjetas", owner: "usr_elena", description: "Aplicación OAuth del equipo Tarjetas." },
  { id: "bot_conciliacion", kind: "robot", name: "Robot de conciliación", team: "Pagos", owner: "usr_carla", description: "Cuenta de servicio que cuadra pagos cada noche." },
  { id: "bot_cargas", kind: "robot", name: "Robot de cargas", team: "Tarjetas", owner: "usr_elena", description: "Cuenta de servicio que importa movimientos." },
  { id: "agt_soporte", kind: "agent", name: "Agente de soporte", team: "Pagos", owner: "usr_carla", risk: "bajo", description: "Agente de IA que responde dudas sobre pagos." },
  { id: "agt_fraude", kind: "agent", name: "Agente antifraude", team: "Tarjetas", owner: "usr_elena", risk: "medio", description: "Agente de IA que marca operaciones sospechosas." },
  { id: "req_carla_lead", kind: "request", name: "Carla pide «Responsable de equipo»", team: "Pagos", requester: "usr_carla", role: "team_lead", description: "Solicitud de autoservicio pendiente de aprobar." },
  { id: "req_bruno_admin", kind: "request", name: "Bruno pide «Administrador de IAM»", team: "Pagos", requester: "usr_bruno", role: "iam_admin", description: "Solicitud de autoservicio pendiente de aprobar." },
];

export interface ActionDef {
  id: string;
  label: string;
  param?: "role" | "risk";
}

export const ACTIONS: Record<Kind, ActionDef[]> = {
  user: [
    { id: "ver", label: "Ver" },
    { id: "editar", label: "Editar perfil" },
    { id: "asignar_rol", label: "Asignar rol", param: "role" },
    { id: "desactivar", label: "Desactivar" },
  ],
  role: [
    { id: "ver", label: "Ver" },
    { id: "solicitar", label: "Solicitar para mí" },
  ],
  app: [
    { id: "ver", label: "Ver" },
    { id: "editar", label: "Editar" },
    { id: "eliminar", label: "Eliminar" },
  ],
  robot: [
    { id: "ver", label: "Ver" },
    { id: "rotar_credenciales", label: "Rotar credenciales" },
    { id: "eliminar", label: "Eliminar" },
  ],
  agent: [
    { id: "ver", label: "Ver" },
    { id: "conceder_permisos", label: "Conceder permisos", param: "risk" },
    { id: "suspender", label: "Suspender" },
  ],
  request: [
    { id: "ver", label: "Ver" },
    { id: "aprobar", label: "Aprobar" },
  ],
};

export const KIND_LABELS: Record<Kind, string> = {
  user: "Usuarios",
  role: "Roles",
  app: "Aplicaciones",
  robot: "Robots (cuentas de servicio)",
  agent: "Agentes de IA",
  request: "Solicitudes de acceso",
};

export const principalBySub = (sub: string): Principal | undefined => PRINCIPALS.find((p) => p.sub === sub);
export const resourceById = (id: string): Resource | undefined => RESOURCES.find((r) => r.id === id);
export const roleById = (id: string): Resource | undefined => ROLES.find((r) => r.id === id);
export const nameOf = (sub?: string): string => (sub ? principalBySub(sub)?.name ?? sub : "—");

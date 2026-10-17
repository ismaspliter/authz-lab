// Motor de decisión: evalúa cada dimensión por separado y las combina.
// permitido = capacidad ∧ ámbito ∧ relación ∧ límite ∧ contexto ∧ ¬prohibición

import { ROLES } from "./model.ts";
import { CONTEXT, LIMITS, PROHIBITIONS, ROLE_GRANTS, hasRelation, inScope, matches, type AuthzRequest, type Grant, type Rule } from "./policy.ts";

export type Status = "ok" | "fallo" | "no_aplica";
export type Dimension = "capacidad" | "ambito" | "relacion" | "limite" | "contexto" | "prohibicion";

export interface DimensionResult {
  dimension: Dimension;
  status: Status;
  detail: string;
  rule?: string;
}

export interface Decision {
  allowed: boolean;
  summary: string;
  dimensions: DimensionResult[];
}

const roleName = (id: string) => ROLES.find((r) => r.id === id)?.name ?? id;

function evalRules(dimension: Dimension, rules: Rule[], r: AuthzRequest, okText: string): DimensionResult {
  const applicable = rules.filter((rule) => rule.applies(r));
  if (applicable.length === 0) return { dimension, status: "no_aplica", detail: "Ninguna regla de esta dimensión afecta a esta acción." };
  for (const rule of applicable) {
    const c = rule.check(r);
    if (!c.ok) return { dimension, status: "fallo", detail: c.detail, rule: `${rule.id} · ${rule.text}` };
  }
  const first = applicable[0];
  const detail = applicable.map((rule) => rule.check(r).detail).filter(Boolean).join(" ") || okText;
  return { dimension, status: "ok", detail, rule: applicable.map((x) => `${x.id} · ${x.text}`).join(" | ") || first.text };
}

export function decide(r: AuthzRequest): Decision {
  const kind = r.resource.kind;
  const perm = `${kind}:${r.action}`;

  // 1. capacidad
  const candidates: { role: string; grant: Grant }[] = [];
  for (const role of r.principal.roles)
    for (const grant of ROLE_GRANTS[role] ?? []) if (matches(grant.perm, kind, r.action)) candidates.push({ role, grant });

  let capacidad: DimensionResult;
  let ambito: DimensionResult;
  let relacion: DimensionResult;

  if (candidates.length === 0) {
    const roles = r.principal.roles.map(roleName).join(", ");
    capacidad = { dimension: "capacidad", status: "fallo", detail: `Ninguno de tus roles (${roles}) incluye «${perm}».` };
    const skip = "No se evalúa: sin capacidad no hay nada que acotar.";
    ambito = { dimension: "ambito", status: "no_aplica", detail: skip };
    relacion = { dimension: "relacion", status: "no_aplica", detail: skip };
  } else {
    // Busca el permiso que mejor encaja: primero uno que cumpla ámbito y relación.
    const scored = candidates.map((c) => {
      const s = inScope(c.grant.scope, r);
      const rel = c.grant.relation ? hasRelation(c.grant.relation, r) : null;
      return { ...c, s, rel, score: (s.ok ? 2 : 0) + (rel === null || rel.ok ? 1 : 0) };
    });
    scored.sort((a, b) => b.score - a.score);
    const best = scored[0];
    capacidad = {
      dimension: "capacidad",
      status: "ok",
      detail: `Tu rol «${roleName(best.role)}» incluye «${best.grant.perm}».`,
      rule: `${roleName(best.role)} → ${best.grant.perm} (ámbito: ${best.grant.scope}${best.grant.relation ? `, relación: ${best.grant.relation.replace(/_/g, " ")}` : ""})`,
    };
    ambito = { dimension: "ambito", status: best.s.ok ? "ok" : "fallo", detail: best.s.detail, rule: `Ámbito «${best.grant.scope}»` };
    relacion = best.rel
      ? { dimension: "relacion", status: best.rel.ok ? "ok" : "fallo", detail: best.rel.detail, rule: `Exige: ${best.grant.relation?.replace(/_/g, " ")}` }
      : { dimension: "relacion", status: "no_aplica", detail: "Este permiso no exige ningún vínculo con el recurso." };
  }

  const limite = evalRules("limite", LIMITS, r, "Dentro de tus límites.");
  const contexto = evalRules("contexto", CONTEXT, r, "El contexto de la sesión es suficiente.");
  const prohibicion = evalRules("prohibicion", PROHIBITIONS, r, "Ninguna prohibición lo impide.");

  const dimensions = [capacidad, ambito, relacion, limite, contexto, prohibicion];
  const failed = dimensions.filter((d) => d.status === "fallo");
  const allowed = failed.length === 0;

  let summary: string;
  if (allowed) summary = "Permitido: se cumplen todas las dimensiones.";
  else if (prohibicion.status === "fallo") summary = "Denegado por una prohibición, que gana a cualquier permiso.";
  else summary = `Denegado: falla ${failed.map((d) => LABELS[d.dimension].toLowerCase()).join(", ")}.`;

  return { allowed, summary, dimensions };
}

export const LABELS: Record<Dimension, string> = {
  capacidad: "Capacidad",
  ambito: "Ámbito",
  relacion: "Relación",
  limite: "Límite",
  contexto: "Contexto",
  prohibicion: "Prohibición",
};

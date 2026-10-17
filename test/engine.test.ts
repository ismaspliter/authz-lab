// Tests del motor de reglas: node --test test/
import { test } from "node:test";
import assert from "node:assert/strict";
import { decide } from "../src/engine.ts";
import { principalBySub, resourceById, type Risk } from "../src/model.ts";

const MFA = { mfa: true, managedDevice: true };
const NO_MFA = { mfa: false, managedDevice: true };

function ask(sub: string, resId: string, action: string, opts: { role?: string; risk?: Risk; ctx?: typeof MFA } = {}) {
  const principal = principalBySub(sub);
  const resource = resourceById(resId);
  assert.ok(principal && resource);
  return decide({ principal, resource, action, params: { role: opts.role, risk: opts.risk }, context: opts.ctx ?? MFA });
}
const dim = (d: ReturnType<typeof decide>, name: string) => d.dimensions.find((x) => x.dimension === name)!.status;

test("la administradora puede casi todo", () => {
  assert.equal(ask("usr_ana", "bot_cargas", "rotar_credenciales").allowed, true);
  assert.equal(ask("usr_ana", "usr_carla", "asignar_rol", { role: "team_lead" }).allowed, true);
});

test("capacidad: Alex (empleado) no puede editar apps", () => {
  const d = ask("usr_7f3a9c", "app_pasarela", "editar");
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "capacidad"), "fallo");
});

test("ámbito: Carla no ve la app de Tarjetas", () => {
  const d = ask("usr_carla", "app_extractos", "ver");
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "ambito"), "fallo");
  assert.equal(ask("usr_carla", "app_pasarela", "ver").allowed, true);
});

test("relación: Carla solo rota credenciales de sus robots", () => {
  assert.equal(ask("usr_carla", "bot_conciliacion", "rotar_credenciales").allowed, true);
  const d = ask("usr_bruno", "bot_conciliacion", "rotar_credenciales");
  assert.equal(d.allowed, true, "Bruno, como responsable, no necesita ser propietario");
});

test("relación: Bruno aprueba la solicitud de Carla porque es su responsable", () => {
  const d = ask("usr_bruno", "req_carla_lead", "aprobar");
  assert.equal(d.allowed, true);
  assert.equal(dim(d, "relacion"), "ok");
});

test("prohibición: nadie aprueba su propia solicitud, ni la administradora", () => {
  const d = ask("usr_bruno", "req_bruno_admin", "aprobar");
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "prohibicion"), "fallo");
});

test("límite: Bruno no puede dar un rol de nivel superior al suyo", () => {
  const d = ask("usr_bruno", "usr_carla", "asignar_rol", { role: "iam_admin" });
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "limite"), "fallo");
  assert.equal(ask("usr_bruno", "usr_carla", "asignar_rol", { role: "team_lead" }).allowed, true);
});

test("prohibición: nadie se asigna roles a sí mismo", () => {
  const d = ask("usr_ana", "usr_ana", "asignar_rol", { role: "auditor" });
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "prohibicion"), "fallo");
});

test("contexto: sin MFA no se rotan credenciales", () => {
  const d = ask("usr_carla", "bot_conciliacion", "rotar_credenciales", { ctx: NO_MFA });
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "contexto"), "fallo");
});

test("contexto: eliminar exige dispositivo gestionado", () => {
  const d = ask("usr_ana", "app_pasarela", "eliminar", { ctx: { mfa: true, managedDevice: false } });
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "contexto"), "fallo");
});

test("límite de riesgo: Carla concede medio pero no alto a su agente", () => {
  assert.equal(ask("usr_carla", "agt_soporte", "conceder_permisos", { risk: "medio" }).allowed, true);
  const d = ask("usr_carla", "agt_soporte", "conceder_permisos", { risk: "alto" });
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "limite"), "fallo");
});

test("prohibición: ningún agente recibe riesgo crítico, ni de la administradora", () => {
  const d = ask("usr_ana", "agt_soporte", "conceder_permisos", { risk: "crítico" });
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "prohibicion"), "fallo");
});

test("auditor: lo ve todo, no cambia nada", () => {
  assert.equal(ask("usr_david", "agt_fraude", "ver").allowed, true);
  const d = ask("usr_david", "agt_fraude", "suspender");
  assert.equal(d.allowed, false);
  assert.equal(dim(d, "prohibicion"), "fallo");
});

test("autoservicio: cualquiera puede solicitar un rol y editar su perfil", () => {
  assert.equal(ask("usr_7f3a9c", "developer", "solicitar").allowed, true);
  assert.equal(ask("usr_7f3a9c", "usr_7f3a9c", "editar").allowed, true);
  assert.equal(ask("usr_7f3a9c", "usr_carla", "editar").allowed, false);
});

test("cada decisión trae las seis dimensiones", () => {
  const d = ask("usr_elena", "agt_fraude", "ver");
  assert.deepEqual(d.dimensions.map((x) => x.dimension), ["capacidad", "ambito", "relacion", "limite", "contexto", "prohibicion"]);
});

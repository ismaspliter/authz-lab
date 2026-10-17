// Authz Lab · interfaz. Toda decisión la toma el servidor; aquí solo se muestra.

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const DIM_LABELS = { capacidad: "Capacidad", ambito: "Ámbito", relacion: "Relación", limite: "Límite", contexto: "Contexto", prohibicion: "Prohibición" };
const ERRORS = {
  access_denied: "Has rechazado el acceso en el IAM Lab.",
  state_invalido: "El parámetro state no coincidía: se ha descartado la respuesta (protección contra CSRF).",
  sin_transaccion: "No se encontró el inicio de sesión en curso. Vuelve a intentarlo.",
  canje_fallido: "El IAM Lab no aceptó el código de autorización.",
  id_token_invalido: "El id_token no superó la validación (firma, emisor, audiencia, caducidad o nonce).",
};

let me = null;
let catalog = null;
let current = null; // { resource, action }
let managedDevice = true;
try { managedDevice = localStorage.getItem("authz-device") !== "0"; } catch {}

async function getJson(url, init) {
  const res = await fetch(url, { credentials: "same-origin", ...init });
  if (res.status === 401) return null;
  return res.json();
}

// ---------- identidad ----------

function renderIdentity() {
  const { claims, profile } = me;
  const mfa = claims.amr.includes("mfa");
  const mins = Math.max(0, Math.round((claims.exp - Date.now() / 1000) / 60));
  $("identity").innerHTML = `
    <div class="who">
      <p class="label">Sesión iniciada en el IAM Lab</p>
      <h1>${esc(claims.name || claims.sub)}</h1>
      <p class="muted">${profile ? `${esc(profile.title)} · equipo ${esc(profile.team)}` : "Sin ficha en el directorio de la empresa"}</p>
      <div class="chips">
        ${profile ? profile.roles.map((r) => `<span class="chip">${esc(r)}</span>`).join("") : ""}
        ${profile ? `<span class="chip">nivel ${profile.level}</span><span class="chip">riesgo máx. ${esc(profile.maxRisk)}</span>` : ""}
        ${profile && profile.manager ? `<span class="chip">responsable: ${esc(profile.manager)}</span>` : ""}
      </div>
    </div>
    <div class="ctx">
      <p class="label">Contexto de la sesión</p>
      <div class="ctx-row"><span class="pill ${mfa ? "ok" : "bad"}">${mfa ? "✓ Con MFA" : "✕ Sin MFA"}</span><small>Viene del claim <code>amr</code> del id_token. Para cambiarlo, vuelve a iniciar sesión.</small></div>
      <label class="ctx-row switch"><input type="checkbox" id="device" ${managedDevice ? "checked" : ""}> <span>Dispositivo gestionado por la empresa</span></label>
      <small class="muted">La sesión caduca en ${mins} min.</small>
      <div class="actions"><a class="btn" href="/logout">Cerrar sesión</a><a class="btn" href="/login">Cambiar de usuario</a></div>
    </div>`;
  $("device").addEventListener("change", async (e) => {
    managedDevice = e.target.checked;
    try { localStorage.setItem("authz-device", managedDevice ? "1" : "0"); } catch {}
    await loadCatalog();
    if (current) decide();
  });
}

// ---------- recursos ----------

function meta(r) {
  const bits = [];
  if (r.team) bits.push(`equipo ${r.team}`);
  if (r.owner) bits.push(`propietario: ${r.owner}`);
  if (r.requester) bits.push(`la pide: ${r.requester}`);
  if (r.risk) bits.push(`riesgo ${r.risk}`);
  if (r.level) bits.push(`nivel ${r.level}`);
  return bits.join(" · ");
}

async function loadCatalog() {
  catalog = await getJson(`/api/catalog?device=${managedDevice ? 1 : 0}`);
  if (!catalog) return location.reload();
  $("resources").innerHTML = catalog.kinds
    .map(
      (k) => `
    <section class="kind">
      <h2 class="section-title">${esc(k.label)}</h2>
      <div class="cards">
        ${k.resources
          .map(
            (r) => `
          <article class="card">
            <h3>${esc(r.name)}</h3>
            <p class="card-meta">${esc(meta(r))}</p>
            <p class="card-desc">${esc(r.description)}</p>
            <div class="acts">
              ${r.actions
                .map(
                  (a) =>
                    `<button class="act ${a.allowed ? "yes" : "no"}" data-res="${esc(r.id)}" data-act="${esc(a.id)}" aria-label="${esc(a.label)} ${esc(r.name)}: ${a.allowed ? "permitido" : "denegado"}"><span aria-hidden="true">${a.allowed ? "✓" : "✕"}</span>${esc(a.label)}</button>`
                )
                .join("")}
            </div>
          </article>`
          )
          .join("")}
      </div>
    </section>`
    )
    .join("");
  document.querySelectorAll(".act").forEach((b) =>
    b.addEventListener("click", () => {
      current = { resource: b.dataset.res, action: b.dataset.act, role: "team_lead", risk: "bajo" };
      decide(true);
    })
  );
  renderRules();
}

function findAction() {
  for (const k of catalog.kinds)
    for (const r of k.resources) if (r.id === current.resource) return { r, a: r.actions.find((x) => x.id === current.action) };
  return {};
}

// ---------- decisión ----------

async function decide(scroll = false) {
  const { r, a } = findAction();
  if (!r || !a) return;
  const d = await getJson("/api/authorize", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ resourceId: current.resource, action: current.action, role: current.role, risk: current.risk, managedDevice }),
  });
  if (!d) return location.reload();

  let param = "";
  if (a.param === "role")
    param = `<label class="param">Rol a asignar <select id="param">${catalog.roles.map((x) => `<option value="${x.id}" ${x.id === current.role ? "selected" : ""}>${esc(x.name)} (nivel ${x.level})</option>`).join("")}</select></label>`;
  if (a.param === "risk")
    param = `<label class="param">Riesgo de los permisos <select id="param">${catalog.risks.map((x) => `<option value="${x}" ${x === current.risk ? "selected" : ""}>${esc(x)}</option>`).join("")}</select></label>`;

  $("decision-body").innerHTML = `
    <h2 class="question">¿Puede ${esc(me.claims.name || "este usuario")} <strong>${esc(a.label.toLowerCase())}</strong> «${esc(r.name)}»?</h2>
    ${param}
    <div class="verdict ${d.allowed ? "ok" : "bad"}"><strong>${d.allowed ? "✓ Permitido" : "✕ Denegado"}</strong><p>${esc(d.summary)}</p></div>
    <ol class="trace">
      ${d.dimensions
        .map(
          (x) => `<li class="${x.status}">
            <span class="ico" aria-hidden="true">${x.status === "ok" ? "✓" : x.status === "fallo" ? "✕" : "–"}</span>
            <div><strong>${DIM_LABELS[x.dimension]}</strong><span class="st">${x.status === "ok" ? "cumple" : x.status === "fallo" ? "no cumple" : "no aplica"}</span>
            <p>${esc(x.detail)}</p>${x.rule ? `<small>${esc(x.rule)}</small>` : ""}</div>
          </li>`
        )
        .join("")}
    </ol>`;
  const sel = $("param");
  if (sel)
    sel.addEventListener("change", () => {
      if (a.param === "role") current.role = sel.value;
      else current.risk = sel.value;
      decide();
    });
  document.querySelectorAll(".act.sel").forEach((x) => x.classList.remove("sel"));
  document.querySelector(`.act[data-res="${CSS.escape(current.resource)}"][data-act="${CSS.escape(current.action)}"]`)?.classList.add("sel");
  if (scroll && window.matchMedia("(max-width: 900px)").matches) $("decision").scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------- reglas ----------

function renderRules() {
  const r = catalog.rules;
  const list = (items) => `<ul>${items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>`;
  $("rules-body").innerHTML = `
    <h3>Capacidad, ámbito y relación (por rol)</h3>
    ${r.capacidad.map((c) => `<p class="rule-role">${esc(c.role)}</p>${list(c.grants)}`).join("")}
    <h3>Límite</h3>${list(r.limite)}
    <h3>Contexto</h3>${list(r.contexto)}
    <h3>Prohibición (siempre gana)</h3>${list(r.prohibicion)}`;
}

// ---------- arranque ----------

(async () => {
  const q = new URLSearchParams(location.search);
  if (q.has("error")) {
    $("error").textContent = ERRORS[q.get("error")] || `Error al iniciar sesión: ${q.get("error")}`;
    $("error").hidden = false;
    history.replaceState(null, "", "/");
  }
  me = await getJson("/api/me");
  if (!me) {
    $("welcome").hidden = false;
    return;
  }
  $("app").hidden = false;
  renderIdentity();
  await loadCatalog();
})();

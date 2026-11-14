// Tráfico en vivo: dibuja el recorrido de cada petición mientras ocurre.
// Sin dependencias: HTML + CSS + Web Animations API. Con prefers-reduced-motion
// no hay vuelos ni pulsos: solo se marcan los nodos, las reglas y el registro.

const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
const still = () => motion.matches || typeof Element.prototype.animate !== "function";
const wait = (ms) => new Promise((r) => setTimeout(r, still() ? 0 : ms));

export const DIMS = [
  ["capacidad", "Capacidad"],
  ["ambito", "Ámbito"],
  ["relacion", "Relación"],
  ["limite", "Límite"],
  ["contexto", "Contexto"],
  ["prohibicion", "Prohibición"],
];
const MARK = { ok: "✓", fallo: "✕", no_aplica: "–" };

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/**
 * Monta el panel en `root`.
 * nodes: [{ id, name, sub }] de izquierda a derecha.
 */
export function mountFlow(root, { nodes, title = "Tráfico en vivo", engineLabel = "motor de reglas · authz-lab" }) {
  root.classList.add("flow");
  root.innerHTML = `
    <div class="flow-head">
      <p class="label">${esc(title)}</p>
      <span class="flow-legend" aria-hidden="true"><i class="req"></i>petición<i class="ok"></i>OK<i class="bad"></i>error</span>
    </div>
    <div class="flow-lane" aria-hidden="true">
      ${nodes
        .map((n, i) => `${i ? '<span class="flow-wire"></span>' : ""}<div class="flow-node" data-node="${esc(n.id)}"><b>${esc(n.name)}</b><small>${esc(n.sub)}</small></div>`)
        .join("")}
    </div>
    <div class="flow-engine" aria-hidden="true">
      <span class="flow-engine-label">${esc(engineLabel)}</span>
      <div class="flow-gates">${DIMS.map(([id, label]) => `<span class="gate" data-dim="${id}"><i></i>${label}</span>`).join("")}</div>
    </div>
    <ol class="flow-log" aria-label="Registro de peticiones"></ol>`;

  const lane = root.querySelector(".flow-lane");
  const logEl = root.querySelector(".flow-log");
  const node = (id) => lane.querySelector(`[data-node="${id}"]`);
  const gates = [...root.querySelectorAll(".gate")];
  let gen = 0;
  let live = [];

  function center(id) {
    const n = node(id);
    return { x: n.offsetLeft + n.offsetWidth / 2, y: n.offsetTop + n.offsetHeight / 2 };
  }

  function stop() {
    for (const a of live) a.cancel();
    live = [];
    lane.querySelectorAll(".packet").forEach((p) => p.remove());
    lane.querySelectorAll(".flow-node.busy").forEach((n) => n.classList.remove("busy"));
  }

  /** Empieza una ejecución nueva y cancela la anterior. */
  function begin() {
    stop();
    const my = ++gen;
    const alive = () => my === gen;

    const run = {
      alive,

      /** Vuela una píldora con `label` de un nodo a otro. tone: req | ok | bad */
      async send(from, to, label, tone = "req") {
        if (!alive()) return;
        node(to).classList.add("hit");
        setTimeout(() => node(to).classList.remove("hit"), 600);
        if (still()) return;
        const a = center(from);
        const b = center(to);
        const p = document.createElement("span");
        p.className = `packet ${tone}`;
        p.textContent = label;
        lane.append(p);
        const w = p.offsetWidth;
        const h = p.offsetHeight;
        const arc = b.x > a.x ? -22 : 22; // ida por arriba, vuelta por abajo
        const at = (x, y, s = 1) => `translate(${x - w / 2}px, ${y - h / 2}px) scale(${s})`;
        const anim = p.animate(
          [
            { transform: at(a.x, a.y, 0.6), opacity: 0 },
            { transform: at(a.x + (b.x - a.x) * 0.15, a.y + arc * 0.6), opacity: 1, offset: 0.15 },
            { transform: at((a.x + b.x) / 2, (a.y + b.y) / 2 + arc), opacity: 1, offset: 0.5 },
            { transform: at(b.x - (b.x - a.x) * 0.15, b.y + arc * 0.6), opacity: 1, offset: 0.85 },
            { transform: at(b.x, b.y, 0.6), opacity: 0 },
          ],
          { duration: 620, easing: "cubic-bezier(.45,.05,.35,1)" }
        );
        live.push(anim);
        try {
          await anim.finished;
        } catch {}
        p.remove();
      },

      /** Halo en el nodo mientras la petición real está en curso. */
      busy(id, on) {
        if (alive()) node(id).classList.toggle("busy", on);
      },

      resetGates() {
        if (!alive()) return;
        for (const g of gates) {
          g.className = "gate";
          g.querySelector("i").textContent = "";
        }
      },

      /** Enciende las seis puertas en orden con el resultado real del motor. */
      async gates(dimensions) {
        this.resetGates();
        const byDim = Object.fromEntries((dimensions || []).map((d) => [d.dimension, d.status]));
        for (const g of gates) {
          if (!alive()) return;
          const st = byDim[g.dataset.dim] || "no_aplica";
          g.classList.add("scan");
          await wait(110);
          if (!alive()) return;
          g.classList.remove("scan");
          g.classList.add(st);
          g.querySelector("i").textContent = MARK[st];
          if (!still()) {
            const k = st === "fallo"
              ? [{ transform: "translateX(0)" }, { transform: "translateX(-3px)" }, { transform: "translateX(3px)" }, { transform: "translateX(0)" }]
              : [{ transform: "scale(.9)" }, { transform: "scale(1.06)" }, { transform: "scale(1)" }];
            live.push(g.animate(k, { duration: st === "fallo" ? 260 : 220, easing: "ease-out" }));
          }
        }
      },

      /** Ráfaga sobre todas las puertas (p. ej. cuando el motor evalúa el catálogo entero). */
      async sweep() {
        this.resetGates();
        for (const g of gates) {
          if (!alive()) return;
          g.classList.add("scan");
          await wait(45);
        }
        await wait(120);
        if (alive()) gates.forEach((g) => g.classList.remove("scan"));
      },

      log(html, tone = "") {
        if (!alive()) return;
        const li = document.createElement("li");
        li.className = tone;
        li.innerHTML = html;
        logEl.append(li);
        while (logEl.children.length > 6) logEl.firstElementChild.remove();
        if (!still()) li.animate([{ opacity: 0, transform: "translateY(4px)" }, { opacity: 1, transform: "none" }], { duration: 200, easing: "ease-out" });
      },

      clearLog() {
        if (alive()) logEl.innerHTML = "";
      },

      wait: (ms) => wait(ms),
    };
    return run;
  }

  return { begin, stop };
}

/** Lee la cabecera Server-Timing que añade el Worker (p. ej. jwks;desc="cache"). */
export function serverTiming(res) {
  const out = {};
  for (const part of (res.headers.get("server-timing") || "").split(",")) {
    const m = part.trim().match(/^([\w-]+)(?:;.*?desc="?([^";]*)"?)?/);
    if (m) out[m[1]] = m[2] ?? true;
  }
  return out;
}

export { esc, still };

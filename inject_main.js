/**
 * inject_main.js — Puente al "mundo MAIN" (manifest: content_scripts con world:"MAIN").
 *
 * Corre en el MISMO contexto JS que la página (no en el mundo aislado) y resuelve
 * dos cosas que el content script aislado NO puede:
 *
 *  1. Interceptar attachShadow({mode:"closed"}) — los shadow roots *closed* son
 *     inaccesibles desde el mundo aislado; aquí los marcamos y registramos.
 *  2. Rellenar inputs DENTRO de roots closed: el mundo aislado no llega a esos
 *     nodos; el MAIN sí (comparten DOM, no contexto JS).
 *
 * Protocolo con content.js (mundo aislado), vía CustomEvent en document/window:
 *   MAIN  → aislado : 'lp:closed-shadow'  (hay un root closed nuevo: re-escanea)
 *   aislado → MAIN  : 'lp:fill-request'   (detail = JSON {username, password})
 *   MAIN  → aislado : 'lp:fill-result'    (detail = JSON {filled})
 *
 * SECURITY: las credenciales viajan en claro por el detalle del evento. Un script
 * de la página podría escuchar 'lp:fill-request'. Para el escenario de este proyecto
 * (firmware LAN propio, servidores de desarrollo) el tradeoff es aceptable y el
 * alcance queda limitado a hosts locales por el guard de content.js.
 */
(() => {
  'use strict';

  // Idempotencia defensiva (extensiones recargadas no deben apilar hooks).
  if (window.__localPassMain) return;
  window.__localPassMain = true;

  const CLOSED_HOST_ATTR = 'data-lp-closed-host';

  // ---------------------------------------------------------------- 1) hook attachShadow

  const originalAttachShadow = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function attachShadowHook(init) {
    const root = originalAttachShadow.call(this, init);
    try {
      if (root && init && init.mode === 'closed') {
        this.setAttribute(CLOSED_HOST_ATTR, ''); // marcador visible al mundo aislado
        (window.__lpClosedRoots = window.__lpClosedRoots || []).push(root);
        // Hay material nuevo: el mundo aislado agenda un re-escaneo.
        document.dispatchEvent(new CustomEvent('lp:closed-shadow'));
      }
    } catch { /* jamás interrumpir el render de la página */ }
    return root;
  };

  // ---------------------------------------------------------------- 2) seteo nativo

  /** Misma técnica que jsSet() en content.js: setter prototípico + input/change. */
  function nativeSet(el, value) {
    const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (d && d.set) d.set.call(el, value); else el.value = value;
    el.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  /** Carga "razonable" de usuario/contraseña dentro de un root closed. */
  function fillInsideClosedRoots(data) {
    const roots = window.__lpClosedRoots || [];
    let filled = false;
    for (const root of roots) {
      if (!(root instanceof ShadowRoot)) continue;
      const pwd = root.querySelector('input[type="password"]:not([disabled]):not([readonly])');
      if (pwd && !pwd.value && data.password) {
        nativeSet(pwd, data.password);
        filled = true;
      }
      const user = root.querySelector(
        'input[type="text"]:not([disabled]):not([readonly]), ' +
        'input[type="email"]:not([disabled]):not([readonly]), ' +
        'input[type="tel"]:not([disabled]):not([readonly])');
      if (user && !user.value && data.username) nativeSet(user, data.username);
    }
    return filled;
  }

  // ---------------------------------------------------------------- 3) servicio de fill

  window.addEventListener('lp:fill-request', (ev) => {
    let data;
    try { data = JSON.parse(ev.detail || '{}'); } catch { return; }
    if (typeof data.password !== 'string' || !data.password) return;

    const filled = fillInsideClosedRoots(data);
    document.dispatchEvent(new CustomEvent('lp:fill-result', {
      detail: JSON.stringify({ filled }),
    }));
  });
})();

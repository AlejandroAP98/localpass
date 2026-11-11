/**
 * content.js — Inyección en el DOM: detección, autocompletado y captura de envíos.
 *
 * Pilares técnicos:
 *  1. Escaneo profundo: atraviesa Shadow DOM (open) con deepQueryAll().
 *  2. SPA-ready: MutationObserver con debounce para inputs creados dinámicamente
 *     (React/Vue/Angular), incluyendo reruns cuando el formulario aparece tarde.
 *  3. Frameworks-friendly: jsSet() escribe el value con el setter nativo de
 *     HTMLInputElement y dispara `input` + `change` burbujeantes, de modo que
 *     tanto listeners ligeros (oninput/onchange) como sistemas reactivos
 *     (v-model de Vue, ngModel de Angular, onChange de React controlado) lo ven.
 *  4. Captura: 'submit' en fase de captura + heurística de clic para formularios
 *     SIN <form> (admins de router/drivers que montan login en <div>).
 */
(() => {
  'use strict';

  // ------------------------------------------------------------------ constantes

  const RESCAN_DEBOUNCE_MS = 200;
  const SAVE_DEBOUNCE_MS = 150;
  const MAX_PARENT_WALK = 5;          // cuántos niveles de <div> subimos buscando el "form" lógico
  const UNFILLABLE_HINTS = ['search', 'token', 'otp', 'captcha'];

  // Etiquetas típicas de botón de login (para formularios sin <form>).
  const LOGIN_LABEL_RE =
    /entrar|acceder|iniciar\s*s(e|é)si[oó]n|log\s?in|log\s?on|sign\s?in|submit|conect/i;

  /**
   * Pista de "campo de usuario": SOLO palabras completas. Los límites \b evitan
   * el falso positivo del incidente real: id="loginform-password" casaba por el
   * prefijo "login" → el content script rellenó el password con el username.
   * Cubre inglés y español ('usuario', 'cuenta', 'acceso').
   */
  const USERNAME_HINT_RE =
    /\b(user(name)?|email|mail|login|logon|account|acc(?:ount)?|auth|identifier|usuario|acceso|cuenta)\b/i;

  const attached = new WeakSet(); // evita re-autocompletar el mismo input dos veces

  /**
   * Diagnóstico: console.debug('[LocalPass] …') GATED por el flag `debug` en
   * chrome.storage.local (checkbox del popup → "Seguridad"). Sin flag, no escribe
   * NADA en la consola de las páginas (antes siempre legible en nivel Verbose).
   */
  let DEBUG = false;
  (async () => {
    try { const { debug } = await chrome.storage.local.get('debug'); DEBUG = !!debug; } catch {}
  })();
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && 'debug' in changes) DEBUG = !!changes.debug.newValue;
  });
  function dbg(...args) { if (DEBUG) console.debug('[LocalPass]', ...args); }

  // ------------------------------------------------------------------ mensajería con el SW

  /** sendMessage con promesa tolerante (SW dormido / portal cerrado → null). */
  function sendBgMessage(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (res) => {
          void chrome.runtime.lastError; // se ignora: el siguiente disparo reintenta
          resolve(res || null);
        });
      } catch { resolve(null); }
    });
  }

  /** ¿La contraseña maestra está activa (con o sin desbloqueo)? */
  async function cryptoEnabled() {
    try {
      return !!Vault.cryptoOf(await Vault.load());
    } catch { return false; }
  }

  /**
   * Secreto de una entrada → password en claro.
   *  - Entrada legacy (texto plano): se decodifica localmente como siempre.
   *  - Entrada cifrada: la autoridad de descifrado es el service worker
   *    (única capa con la llave en RAM de sesión). El RESULTADO se cachea por
   *    id en memoria del frame: el arranque en frío del SW (~200-600 ms) solo
   *    se paga UNA vez por entrada y por página; los re-fills (foco, rescan)
   *    son instantáneos. La caché muere con la página (y con lock/borrado):
   *    tras disable-master entra vieja (mema bien: ya estaba desbloqueado).
   */
  const secretCache = new Map();
  async function resolveSecret(entry) {
    if (!entry || !entry.secret) return '';
    if (entry.secret.enc !== true) return entry.secret.plain || '';
    if (secretCache.has(entry.id)) return secretCache.get(entry.id);
    const res = await sendBgMessage({ type: 'vault:decrypt', blob: entry.secret });
    const password = (res && res.ok && typeof res.password === 'string') ? res.password : '';
    if (password) {
      // tope defensivo de memoria por única ocurrencia de página anormal
      if (secretCache.size > 50) secretCache.clear();
      secretCache.set(entry.id, password);
    }
    return password;
  }

  // ------------------------------------------------------------------ guarda de ámbito

  /**
   * Con el patrón https-wildcard inyectamos en MUCHAS más URLs que las que nos interesan.
   * Este `return` temprano restringe la actividad a hosts locales/privados
   * (localhost, 10.x, 172.16-31.x, 192.168.x, .local…), con o sin TLS.
   * Todo el resto del módulo queda inerte en sitios públicos.
   */
  if (!Vault.isLocalTarget(window.location.hostname)) return;

  // ------------------------------------------------------------------ escaneo profundo (Shadow DOM)

  /**
   * querySelectorAll que también desciende en los shadowRoot "open" de cada elemento.
   *
   * BUG CRÍTICO CORREGIDO: antes el guard era `!(node instanceof Element)` y el
   * stack arranca con `document` (instancia de *Document*, no de *Element*) → el
   * primer pop se descartaba y `querySelectorAll` jamás recorría el árbol del
   * documento: TODOS los escaneos devolvían [] y solo el fill por foco funcionaba.
   * Ahora Document/ShadowRoot/Element son scopes válidos de recorrido.
   */
  function deepQueryAll(scope, selector) {
    const out = [];
    const stack = [scope instanceof Document || scope instanceof ShadowRoot || scope instanceof Element ? scope : document];
    while (stack.length) {
      const node = stack.pop();
      const isDocOrRoot = node instanceof Document || node instanceof ShadowRoot;
      if (!(isDocOrRoot || node instanceof Element)) continue;
      // matches() solo existe en Element.
      if (node instanceof Element && node.matches(selector)) out.push(node);
      if (node instanceof Element && node.shadowRoot) stack.push(node.shadowRoot);
      // querySelectorAll no devuelve al propio nodo ni nodos de shadow roots:
      // los roots se recorren explícitamente vía stack (sin duplicados).
      stack.push(...node.querySelectorAll(selector));
    }
    return out;
  }

  // ------------------------------------------------------------------ visibilidad y tipado de inputs

  function isVisible(el) {
    const cs = window.getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') return false;
    if (Number(el.getClientRects().length) === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }

  /** Un input es "tratable" si no está muerto, no es oculto tipo honeypot y no rastrea tokens.
   *  Excepción: el elemento EN FOCO es por definición el objetivo del usuario; los
   *  overlays/animaciones de estos widgets pueden hacer fallar nuestra heurística
   *  de visibilidad en el instante del scan y no deben bloquear el fill pedido
   *  explícitamente con un click. */
  function isFillable(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    if (el.disabled || el.readOnly) return false;
    const name = (el.name || el.id || '').toLowerCase();
    if (UNFILLABLE_HINTS.some((h) => name.includes(h))) return false;
    if (document.activeElement === el) return true; // foco explícito = confianza
    return isVisible(el);
  }

  // ------------------------------------------------------------------ seteo "framework-friendly"

  /**
   * Escribe `value` en un input de forma que TODOS los listeners lo detecten:
   *  - usa el setter prototípico (evita el "value shadowing" de inputs React controlados)
   *  - dispara InputEvent('input') y Event('change'), ambos burbujeantes
   */
  function jsSet(el, value) {
    const proto = HTMLInputElement.prototype;
    const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
    if (descriptor && descriptor.set) {
      descriptor.set.call(el, value);
    } else {
      el.value = value;
    }
    el.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // ------------------------------------------------------------------ heurística: campos de login

  /** Ordena candidatos del documento por "cercanía DOM" al password (los de su mismo subárbol primero). */
  function findUsernamePasswordPairs(scope = document) {
    const passwords = deepQueryAll(scope, 'input[type="password"]')
      .filter(isFillable);
    return passwords.map((pwd) => ({ pwd, user: findUsername(pwd) }));
  }

  /**
   * Dado un input password, busca el input de usuario "asociado".
   * Estrategia: subimos por ancestros (hasta MAX_PARENT_WALK) y, en el primer
   * contenedor que tenga algún input de texto/email/tel usable, elegimos el que
   * esté ANTES del password en orden documental (patrón clásico user→pass) o el primero.
   */
  function findUsername(pwd) {
    let container = pwd.parentElement;
    for (let i = 0; i < MAX_PARENT_WALK && container; i++) {
      const candidates = Array.from(
        container.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"]')
      ).filter(isFillable);
      if (candidates.length) {
        // Preferimos un campo cuyo name/id huela a "user"/"email"/"login".
        const hinted = candidates.find((c) =>
          USERNAME_HINT_RE.test(`${c.name}|${c.id}|${c.className}`));
        // En orden documental, el más cercano ANTERIOR al password.
        const previous = candidates
          .filter((c) => c.compareDocumentPosition(pwd) & Node.DOCUMENT_POSITION_PRECEDING)
          .pop();
        return hinted || previous || candidates[0];
      }
      container = container.parentElement;
    }
    return null;
  }

  // ------------------------------------------------------------------ autocompletado

  /**
   * Aviso "hay varias credenciales para este host" — máximo una vez por página.
   */
  let hintShown = false;
  let originWarned = false; // huella de origen: 1 aviso por carga
  function hintOnce(n, host) {
    if (hintShown) return;
    hintShown = true;
    showToast(`LocalPass: ${n} credenciales para ${host} — elige desde el popup`);
  }

  /**
   * Rellena los campos con credencial(es) guardadas para este hostname.
   * @param {{fromFocus?: boolean, focused?: Element}} [opts]
   *   fromFocus — el focus del usuario disparó el intento: PERMITE re-rellenar
   *               inputs ya tocados si el sitio los vació tras nuestro fill
   *               (patrón típico de routers que limpian onfocus).
   *   focused   — el input enfocado; con ≥2 credenciales por host permite
   *               hacer match exacto por el usuario YA TECLEADO.
   * @returns {Promise<boolean>} true si REELMENTE rellenó al menos un campo.
   */
  async function attemptAutofill(opts = {}) {
    const host = Vault.hostnameKey(window.location.hostname);
    const entries = await Vault.findByHostname(host);

    const pairs = findUsernamePasswordPairs();
    const pwdRaw = deepQueryAll(document, 'input[type="password"]');
    const closedHosts = document.querySelectorAll('[data-lp-closed-host]');
    // --- diagnóstico clave: si pwdInputs>0 pero pwdUsables==0 → isFillable() descarta;
    //     si pwdInputs==0 (y hay hostsShadowClosed>0) → el login vive en shadow "closed".
    dbg('intento', {
      frame: window.location.href,
      credenciales: entries.length,
      pwdInputs: pwdRaw.length,
      pwdUsables: pairs.length,
      hostsShadowClosed: closedHosts.length,
      disparo: opts.fromFocus ? 'focus' : 'scan',
    });

    if (!entries.length) return false;

    // ---------- huella de orígenes (anti-phishing LAN) ----------
    // Si las credenciales de este host se registraron por orígenes distintos
    // al de la pestaña actual (http↔https, otro puerto), avisamos UNA vez por
    // carga. Mismas credenciales + host igual, pero "puerta" nueva = sospechar.
    const knownOrigins = [...new Set(
      entries.flatMap((e) => Array.isArray(e.origins) ? e.origins : (e.origin ? [e.origin] : [])))];
    if (knownOrigins.length && !knownOrigins.includes(window.location.origin) && !originWarned) {
      originWarned = true;
      showToast(`LocalPass: ⚠ origen nuevo para este host (antes por ${knownOrigins[0]}) — verifica el dispositivo`);
    }
    dbg('origenes conocidos', { actuales: window.location.origin, registrados: knownOrigins });

    let chosen = opts.forcedEntry || null; // credencial elegida en el selector in-page
    if (!chosen && entries.length === 1) {
      chosen = entries[0];
    } else if (!chosen) {
      // ≥2 credenciales: el autocompletado ciego queda desactivado (riesgo de
      // llenar la cuenta equivocada). Dos salidas:
      //   a) match por usuario YA TECLEADO en el campo enfocado;
      //   b) con foco pero sin match → selector in-page (click para elegir).
      const typed = (opts.focused instanceof HTMLInputElement)
        ? (opts.focused.value || '').trim().toLowerCase()
        : '';
      chosen = typed
        ? entries.find((e) => (e.username || '').trim().toLowerCase() === typed)
        : null;
      if (!chosen) {
        if (opts.fromFocus && opts.focused) openCredentialPicker(opts.focused, entries);
        else hintOnce(entries.length, host);
        return false;
      }
      dbg('match multi-credencial por usuario tecleado', { username: chosen.username });
    }

    const username = chosen.username || '';
    // Descifra vía SW si hay maestra activa (ver resolveSecret) o texto plano.
    const password = await resolveSecret(chosen);
    if (!password) return false;

    // ---------- login en DOS PASOS (pantalla "solo usuario") ----------
    // Firmware moderno divide el login: fase 1 = username sin NINGÚN
    // input[type=password] en el DOM (pwdInputs: 0 en diagnóstico). Si no hay
    // pares, rellenamos SOLO el campo de usuario "huérfano"
    // (name/id/class con user|email|login|auth|acc) para no llenar cajas de
    // búsqueda ni filtros al azar.
    if (!pairs.length) {
      // (a) Vía rápida: el campo EN FOCO es el propio campo de usuario — es el
      // caso "click en usuario y espero el fill"; bypass total de escaneos.
      // Cuatro defensas contra el incidente del fill cruzado:
      //   1. solo inputs tipo-texto (el usuario NUNCA va vía solo-usuario),
      //   2. nodo aún conectado al documento (la transición del widget puede
      //      desmontarlo justo tras el focusin),
      //   3. credencial CON username (no rellenar '' en el campo),
      //   4. pista por palabra completa (USERNAME_HINT_RE).
      const f = (opts.fromFocus && opts.focused instanceof HTMLInputElement) ? opts.focused : null;
      const isTextish = f && (f.type === 'text' || f.type === 'email' || f.type === 'tel');
      const hintedField = f && USERNAME_HINT_RE.test(`${f.name}|${f.id}|${f.className}`);
      if (f && f.isConnected && isTextish && hintedField && !f.value && username) {
        jsSet(f, username);
        attached.add(f);
        dbg('paso solo-usuario → rellenado directo (foco)', { id: f.id || f.name });
        announceAutofill();
        return true;
      }

      // (b) Un solo escaneo: inventario de diagnóstico + candidatos "con pinta
      // de usuario". El inventario verá en consola QUÉ descarta a cada input si
      // el fill normal sigue sin aparecer (disabled/readonly/visible/hint).
      const els = deepQueryAll(document,
        'input[type="text"], input[type="email"], input[type="tel"], input:not([type])');
      dbg('paso solo-usuario → inventario', els.map((el) => ({
        id: el.id || '', name: el.name || '', type: el.type,
        disabled: el.disabled, readOnly: el.readOnly,
        visible: isVisible(el),
        onfocus: document.activeElement === el,
        hint: USERNAME_HINT_RE.test(`${el.name}|${el.id}|${el.className}`),
      })));

      const hinted = els
        .filter(isFillable)
        .filter((el) => USERNAME_HINT_RE.test(`${el.name}|${el.id}|${el.className}`));
      dbg('paso solo-usuario', { candidatos: hinted.length });
      let ok = false;
      for (const el of hinted) {
        if (el.value) continue;                            // ya tecleado por el usuario
        if (attached.has(el) && !opts.fromFocus) continue; // ya autocompletado por nosotros
        jsSet(el, username);
        attached.add(el);
        ok = true;
      }
      if (ok) { announceAutofill(); return true; }
      return false;
    }

    let filled = false;

    // ---------- fallback: Shadow DOM "closed" ----------
    // Si hay hosts cerrados (marcados por inject_main.js en el mundo MAIN),
    // delegamos el relleno a ese mundo: es el único que puede tocar sus roots.
    // El listener de 'lp:fill-result' se ocupa del feedback/toast.
    if (closedHosts.length) {
      dbg('fallback shadow closed → lp:fill-request al MAIN', { hosts: closedHosts.length });
      window.dispatchEvent(new CustomEvent('lp:fill-request', {
        detail: JSON.stringify({ username, password }),
      }));
    }

    // Con `focused` acotamos a los pares que contienen ese input concreto:
    // evita rellenar el login equivocado si la página trae dos formularios.
    const relevant = opts.focused
      ? pairs.filter(({ pwd, user }) => opts.focused === pwd || opts.focused === user)
      : pairs;

    for (const { pwd, user } of relevant) {
      if (pwd.value) continue;                          // el usuario ya escribió algo: no pisamos
      if (attached.has(pwd) && !opts.fromFocus) continue; // ya autocompletado; reintentar solo por foco
      if (user && !user.value) jsSet(user, username);
      jsSet(pwd, password);
      attached.add(pwd);
      filled = true;
      dbg('rellenado', { user: username, host });
    }

    // Feedback SOLO cuando hubo fill real y a lo sumo una vez por carga de página:
    // mostrarlo en cada rescan era ruido y, peor, el propio `<div class="lv-toast">`
    // mutaba el DOM y reactivaba el MutationObserver (bucle de toasts).
    if (filled) {
      announceAutofill();
    }
    return filled;
  }

  // Throttle del toast de autocompletado (máx. 1 aviso por carga/_intervalo corto;
  // evita el ping-pong Observer→toast→Observer).
  const AUTOFILL_TOAST_THROTTLE_MS = 30000;
  let autofillAnnouncedAt = 0;

  /** Feedback único de relleno con throttle (fases de dos pasos lo invocan también). */
  function announceAutofill() {
    const now = Date.now();
    if (now - autofillAnnouncedAt <= AUTOFILL_TOAST_THROTTLE_MS) return;
    autofillAnnouncedAt = now;
    showToast('LocalPass: credencial autocompletada');
  }

  // ------------------------------------------------------------------ captura de credenciales

  /** Construye el objeto entrada desde un par (user, pwd) visible en pantalla. */
  function readPair({ user, pwd }) {
    const password = pwd.value || '';
    const username = user ? user.value.trim() : '';
    if (!password) return null; // envíos sin password no nos interesan
    return {
      hostname: window.location.hostname,
      origin: window.location.origin,
      username,
      password,
    };
  }

  /** Guarda (upsert) mostrando feedback. Con maestra activa, la autoridad de
   *  cifrado es el SW ('vault:capture') — el secret sale cifrado por él. */
  async function saveCurrentCredentials() {
    const pairs = findUsernamePasswordPairs().map(readPair);
    const data = pairs.find(Boolean);
    if (!data || !data.username) return; // si no hay username legible, mejor no inventar

    if (await cryptoEnabled()) {
      const res = await sendBgMessage({ type: 'vault:capture', data });
      if (res && res.ok) {
        showToast(`LocalPass: guardadas credenciales de ${data.username}`);
        // badge lo pinta el SW al recibir 'vault:saved' (o el capture)… el
        // content script solo anuncia; el SW emite badge en el propio capture.
      } else {
        showToast('LocalPass: almacén bloqueado — no se guardó');
      }
      return;
    }

    const before = await Vault.findByHostname(data.hostname);
    const existing = before.find((e) => (e.username || '') === data.username &&
      !Vault.isEncrypted(e) && e.secret && e.secret.plain === data.password);
    if (existing) return; // ya está guardada idéntica: no spamear storage

    await Vault.upsert(data);
    showToast(`LocalPass: guardadas credenciales de ${data.username}`);
    // Notificamos al service worker para poner badge (feedback sin abrir popup).
    try { chrome.runtime.sendMessage({ type: 'vault:saved', hostname: data.hostname }); } catch {}
  }

  /** Debounce compartido para múltiples botones/keydowns del mismo envío. */
  let saveTimer = null;
  function scheduleSave() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveCurrentCredentials, SAVE_DEBOUNCE_MS);
  }

  // 1) <form> real: submit Even en fase de captura (los formularios a veces lo previenen igual).
  document.addEventListener('submit', () => { scheduleSave(); }, true);

  // 2) Formularios SIN <form>: clic en botones "login-like" o Enter en el password.
  document.addEventListener('click', (ev) => {
    const btn = ev.target.closest('button, [role="button"], input[type="submit"], a');
    if (!btn) return;
    const label = (btn.innerText || btn.value || btn.getAttribute('aria-label') || '').trim();
    const hasForm = btn.closest('form');
    if (!hasForm && LOGIN_LABEL_RE.test(label)) scheduleSave();
  }, true);

  document.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Enter') return;
    const field = ev.target;
    if (field instanceof HTMLInputElement && field.type === 'password' && !field.closest('form')) {
      scheduleSave();
    }
  }, true);

  // ------------------------------------------------------------------ escaneo dinámico (SPA)

  let scanTimer = null;
  function scheduleRescan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(() => {
      attemptAutofill(); // idempotente: solo toca inputs nunca tocados
    }, RESCAN_DEBOUNCE_MS);
  }

  // Cualquier cambio en el DOM (incluidos childList de terceros por `subtree`)
  // agenda un re-escaneo; así los <input> de React/Vue/Angular montados tarde
  // terminan autocompletados sin listeners por página.
  // EXCEPCIÓN: ignoramos los nodos que son toasts propios (`lv-toast`) — el
  // appendChild del feedback no debe disparar un re-escaneo (bucle toast↔scan).
  const rescanObserver = new MutationObserver((muts) => {
    for (const m of muts) {
      const foreign = Array.from(m.addedNodes).some(
        (n) => !(n instanceof Element && n.classList.contains('lv-toast')));
      if (foreign) { scheduleRescan(); return; }
    }
  });
  rescanObserver.observe(document.documentElement, {
    childList: true, subtree: true,
  });

  // Escaneo inicial oportuno.
  scheduleRescan();

  // ------------------------------------------------------------------ relleno a demanda (foco)

  /**
   * Reintento "a demanda": al enfocar un campo de credenciales, reintentamos el
   * autocompletado. Cubre tres casos reales:
   *   a) SPA/form que se monta DESPUÉS del primer rescan.
   *   b) JS del sitio que LIMPIA los campos en el propio evento focus
   *      (común en UIs de routers por seguridad): con setTimeout(0) llenamos
   *      DESPUÉS de sus handlers.
   *   c) El usuario simplemente hace click en usuario/contraseña esperando el fill.
   * Es seguro reintentar: attemptAutofill() solo toca campos vacíos no-attached.
   */
  document.addEventListener('focusin', (ev) => {
    const el = ev.target;
    if (!(el instanceof HTMLInputElement)) return;
    const t = el.type;
    if (t !== 'password' && t !== 'text' && t !== 'email' && t !== 'tel') return;

    // Diagnóstico del campo enfocado: dirá si su raíz es el document (login
    // "normal") o un shadow root (instradable solo vía mundo MAIN).
    const root = el.getRootNode();
    dbg('focus en campo', {
      id: el.id || '', name: el.name || '', type: el.type,
      raiz: root === document ? 'document' : (root instanceof ShadowRoot ? 'shadow' : 'otro'),
    });

    // Pasamos el campo enfocado y fromFocus=true:
    //  - rellena después de que el sitio ejecute sus handlers (clear on-focus)
    //  - permite re-llenar campos que el sitio vació tras nuestro primer fill
    //  - con varias credenciales, habilita el match por usuario ya tecleado
    setTimeout(() => { attemptAutofill({ fromFocus: true, focused: el }); }, 0);
  }, true);

  // ---------------------------------------------------------------- protocolo con inject_main.js

  // Un shadow root "closed" apareció: hay material nuevo que re-escanear.
  document.addEventListener('lp:closed-shadow', () => { scheduleRescan(); }, true);

  // El mundo MAIN terminó su intento de fill: feedback si rellenó de verdad.
  document.addEventListener('lp:fill-result', (ev) => {
    let ok = false;
    try { ok = JSON.parse(ev.detail || '{}').filled === true; } catch { /* detalle corrupto */ }
    if (!ok) return;
    announceAutofill();
  }, true);

  // ------------------------------------------------------------------ selector in-page (≥2 credenciales)

  let pickerEl = null;

  /** Cierra el selector y su listener de exterior. */
  function removePicker() {
    if (!pickerEl) return;
    pickerEl.remove();
    pickerEl = null;
    document.removeEventListener('mousedown', pickerOutside, true);
  }

  /** Clic fuera → cerrar. */
  function pickerOutside(ev) {
    if (pickerEl && !pickerEl.contains(ev.target)) removePicker();
  }

  /**
   * Menú flotante anclado al campo enfocado con las credenciales del host.
   * Solo se ejecuta en el guard de override (win focus + sin match), de modo
   * que nunca se abre en escaneos automáticos de fondo (sin loops).
   */
  function openCredentialPicker(anchor, entries) {
    if (!entries.length) return;
    removePicker();

    const boxEl = document.createElement('div');
    boxEl.className = 'lv-picker';
    boxEl.style.position = 'fixed';
    boxEl.style.zIndex = '2147483647';
    boxEl.style.minWidth = '220px';
    boxEl.style.maxWidth = '300px';
    boxEl.style.background = '#1f2430';
    boxEl.style.color = '#e6e9ef';
    boxEl.style.border = '1px solid #3a4152';
    boxEl.style.borderRadius = '10px';
    boxEl.style.boxShadow = '0 8px 24px rgba(0,0,0,.4)';
    boxEl.style.overflow = 'hidden';
    boxEl.style.font = '13px/1.4 system-ui, -apple-system, Segoe UI, sans-serif';

    const title = document.createElement('div');
    title.textContent = 'LocalPass — elige una credencial';
    title.style.padding = '8px 12px 6px';
    title.style.fontSize = '11px';
    title.style.fontWeight = '600';
    title.style.color = '#9aa3b2';
    boxEl.appendChild(title);

    for (const entry of entries) {
      const row = document.createElement('button');
      row.type = 'button';
      row.style.cssText =
        'display:flex;justify-content:space-between;gap:12px;width:100%;padding:8px 12px;' +
        'background:none;border:none;border-top:1px solid #2a3040;color:inherit;font:inherit;' +
        'cursor:pointer;text-align:left';
      row.appendChild(Object.assign(document.createElement('span'), { textContent: entry.username || '(sin usuario)' }));
      const h = Object.assign(document.createElement('span'), { textContent: entry.hostname, });
      h.style.cssText = 'color:#9aa3b2;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
      row.appendChild(h);
      row.addEventListener('mouseenter', () => { row.style.background = '#2a3140'; });
      row.addEventListener('mouseleave', () => { row.style.background = 'none'; });
      row.addEventListener('click', async () => {
        removePicker();
        await attemptAutofill({ fromFocus: true, focused: anchor, forcedEntry: entry });
      });
      boxEl.appendChild(row);
    }

    document.documentElement.appendChild(boxEl);

    // Posicionar junto al campo con clamp al viewport.
    const r = anchor.getBoundingClientRect();
    const bw = boxEl.offsetWidth || 240;
    const bh = boxEl.offsetHeight || 120;
    const left = Math.max(8, Math.min(r.left, window.innerWidth - bw - 8));
    const top = Math.max(8, Math.min(r.bottom + 6, window.innerHeight - bh - 8));
    boxEl.style.left = `${left}px`;
    boxEl.style.top = `${top}px`;

    pickerEl = boxEl;
    document.addEventListener('mousedown', pickerOutside, true);
  }

  // ------------------------------------------------------------------ toast in-page

  function showToast(text) {
    const el = document.createElement('div');
    el.className = 'lv-toast';
    el.textContent = text;
    document.documentElement.appendChild(el);
    setTimeout(() => el.remove(), 2600);
  }
})();

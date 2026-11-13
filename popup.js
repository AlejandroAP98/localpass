/**
 * popup.js — Lógica del popup LocalPass.
 *
 * Estados de seguridad (fase 2):
 *   A. sin maestra      → flujo normal + bloque "Activar cifrado"
 *   B. maestra + bloqueado → pantalla de desbloqueo (todo lo demás oculto)
 *   C. maestra + desbloqueado → flujo normal + "🔒 Bloquear ahora" / "Desactivar"
 *
 * Con maestra activa, la lista y el guardado pasan por el service worker
 * (única capa con la llave derivada en RAM; la maestra JAMÁS se persiste).
 * Sin maestra, todo va local vía Vault como en la v1.
 */

(() => {
  'use strict';

  // ------------------------------------------------------------------ refs DOM

  const $ = (sel) => document.querySelector(sel);

  const originPill = $('#origin-pill');
  const mainEl = document.querySelector('main');
  const siteList = $('#site-list');
  const allList = $('#all-list');
  const credForm = $('#cred-form');
  const fId = $('#f-id'), fUser = $('#f-user'), fPass = $('#f-pass');
  const btnCancel = $('#btn-cancel');
  const search = $('#search');
  const summary = $('#summary');
  const toast = $('#toast');
  const rowTemplate = $('#row-template');
  const cntSite = $('#cnt-site'), cntAll = $('#cnt-all');

  // seguridad
  const panelLock = $('#panel-lock');
  const unlockForm = $('#unlock-form');
  const unlockPass = $('#unlock-pass');
  const lockError = $('#lock-error');
  const setupMaster = $('#setup-master');
  const liveMaster = $('#live-master');
  const masterState = $('#master-state');
  const debugToggle = $('#debug-toggle');
  // recuperación de entradas cifradas huérfanas (config de maestra perdida)
  const recoverPanel = $('#recover-vault');
  const recoverPass = $('#m-recover');
  const recoverError = $('#recover-error');

  // ------------------------------------------------------------------ estado

  /** Hostname de la pestaña activa ('' si es una página no-http/https-local). */
  let currentHost = '';
  /** Cache de la lista "plain" para refilrar en vivo sin releer storage. */
  let allEntries = [];
  /** ¿Ya pedimos datos al menos una vez? (evita re-fetch al cambiar de tab). */
  let listFetched = false;
  /** Estado de seguridad vigente: {crypto, unlocked, ttlMs}. */
  let security = { crypto: false, unlocked: false, ttlMs: 0 };
  /** Origen de la pestaña activa (p. ej. "https://10.167.4.162") — para el ⚠ de origen. */
  let currentOrigin = '';

  // ------------------------------------------------------------------ utilidades

  let toastTimer = null;
  function showToast(text) {
    toast.textContent = text;
    toast.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.add('hidden'), 1800);
  }

  /** Mensajería con el SW vía promesas (popup es contexto confiable). */
  async function sendMsg(msg) {
    try {
      return await chrome.runtime.sendMessage(msg);
    } catch {
      return null;
    }
  }

  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      showToast('Contraseña copiada (se limpia en 20 s)');
      setTimeout(() => {
        // Autolimpieza defensiva: si el portapapeles sigue siendo nuestra
        // contraseña, lo vaciamos para no dejarla expuesta http-post-copy.
        navigator.clipboard.readText()
          .then((t) => { if (t === text) navigator.clipboard.writeText(''); })
          .catch(() => {/* permiso de lectura denegado: no pasa nada */});
      }, 20000);
    } catch {
      showToast('No se pudo copiar');
    }
  }

  // ------------------------------------------------------------------ pestaña activa

  /**
   * Lee tab.url con host_permissions (sin permiso "tabs") y decide si la pestaña
   * es un destino gestionable: http/https + host local/privado (localhost, LAN).
   */
  async function detectCurrentSite() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const raw = tab?.url || '';
    let host = '';
    let originLabel = raw;
    try {
      const u = new URL(raw);
      if (/^https?:$/.test(u.protocol)) {
        host = u.hostname.toLowerCase();
        originLabel = u.origin;
      }
    } catch { /* raw no es una URL parseable */ }

    if (host && Vault.isLocalTarget(host)) {
      currentHost = host;
      currentOrigin = u.origin;
      originPill.textContent = originLabel;
      originPill.classList.remove('warn');
      originPill.title = '';
    } else {
      currentHost = '';
      currentOrigin = '';
      originPill.textContent = 'Sitio no compatible';
      originPill.classList.add('warn');
      if (/^https?:/.test(raw)) {
        originPill.title = 'Solo operamos en hosts locales/privados: localhost, 10.x, 172.16–31.x, 192.168.x, .local…';
      } else {
        originPill.title = 'Sitio no gestionable (chrome://, https público, etc.).';
      }
    }
  }

  // ------------------------------------------------------------------ render de listas

  /** Inicial que mostrará el avatar. */
  function initialFor(entry) {
    const src = (entry.username || entry.hostname || '?').trim();
    return src.charAt(0).toUpperCase() || '?';
  }

  /** Hash mínimo y estable (suma de char codes) para elegir tinte del avatar. */
  function hueIndexFor(seed) {
    let h = 0;
    for (const ch of String(seed)) h = (h + ch.charCodeAt(0)) % 997;
    return h % 4;
  }

  /**
   * @param {HTMLUListElement} ul
   * @param {Array} entries  Entradas "plain" (listPlain o vault:list del SW)
   * @param {boolean} showHost propósito informativo (en "Todas" mostramos el dominio)
   */
  function renderList(ul, entries, showHost) {
    ul.replaceChildren();
    if (!entries.length) {
      const empty = document.createElement('li');
      empty.className = 'empty';
      empty.textContent = showHost
        ? 'Nada coincide con el filtro.'
        : 'Aún no hay credenciales. Guarda tu primer login aquí abajo.';
      ul.append(empty);
      return;
    }

    for (const entry of entries) {
      const node = rowTemplate.content.cloneNode(true);
      const row = node.querySelector('.row');
      row.dataset.id = entry.id;

      const avatar = node.querySelector('.avatar');
      avatar.textContent = initialFor(entry);
      avatar.classList.add(`hue-${hueIndexFor(entry.hostname + entry.username) + 1}`);

      node.querySelector('.row-host').textContent = showHost ? entry.hostname : '';
      node.querySelector('.row-user').textContent = entry.username || '(sin usuario)';

      // Huella de origen: si la página actual visita por un origen NUNCA visto
      // al registrar (http↔https u otro puerto), marcamos la fila.
      const originMismatch = currentOrigin
        && Array.isArray(entry.origins) && entry.origins.length > 0
        && !entry.origins.includes(currentOrigin);
      if (originMismatch) {
        const warn = document.createElement('span');
        warn.className = 'origin-warn';
        warn.textContent = '⚠';
        warn.title = `Origen(es) registrado(s): ${entry.origins.join(' · ')}.\nHoy se abre por ${currentOrigin} — verifica que es el dispositivo correcto.`;
        node.querySelector('.row-head').appendChild(warn);
      }

      const pwText = node.querySelector('.pw-text');

      // Estado inicial oculta la contraseña: defecto seguro.
      row.classList.add('pass-hidden');
      pwText.textContent = '••••••••';
      pwText.dataset.plain = entry.password || '';

      node.querySelector('.eye').addEventListener('click', () => {
        const hidden = row.classList.toggle('pass-hidden');
        pwText.textContent = hidden ? '••••••••' : pwText.dataset.plain;
      });
      node.querySelector('.copy').addEventListener('click', () => copyToClipboard(pwText.dataset.plain));
      node.querySelector('.edit').addEventListener('click', () => startEdit(entry));
      node.querySelector('.del').addEventListener('click', () => removeEntry(entry));

      ul.append(node);
    }
  }

  /** Carga las entradas (solo cuando hace falta: cache + listFetched).
   *  refreshLists(true) tras cualquier CRUD/unlock/import. */
  async function refreshLists(force = false) {
    if (force || !listFetched) {
      if (security.crypto) {
        const res = await sendMsg({ type: 'vault:list' });
        allEntries = (res && res.ok && Array.isArray(res.entries)) ? res.entries : [];
      } else {
        allEntries = await Vault.listPlain();
      }
      listFetched = true;
    }

    // Recuperación: blobs enc:true visibles mientras el popup NO tiene cifrado
    // activo → la config de maestra no está disponible (perdida/corrupta) y la
    // única salida es el panel de rescate con la maestra de entonces.
    const orphanEnc = !security.crypto && allEntries.some((e) => e.encrypted);
    recoverPanel.classList.toggle('hidden', !orphanEnc);
    if (!orphanEnc) recoverError.classList.add('hidden');

    const siteEntries = currentHost
      ? allEntries.filter((e) => Vault.hostnameKey(e.hostname) === currentHost)
      : [];
    renderList(siteList, siteEntries, false);

    renderList(allList, filteredEntries(), true);

    // contadores de las tabs (paso UX)
    cntSite.textContent = String(siteEntries.length);
    cntAll.textContent = String(allEntries.length);
    summary.textContent = `${allEntries.length} entrada(s)`;
  }

  function filteredEntries() {
    const q = search.value.trim().toLowerCase();
    if (!q) return allEntries;
    return allEntries.filter((e) =>
      `${e.hostname} ${e.username}`.toLowerCase().includes(q));
  }

  // ------------------------------------------------------------------ seguridad (maestra)

  /** Aplica los flags de `security` a la visibilidad de todos los bloques. */
  function applySecurityUi() {
    const isLocked = security.crypto && !security.unlocked;

    // overlay de bloqueo: tapa el contenido mientras la llave no esté
    panelLock.classList.toggle('hidden', !isLocked);
    mainEl.classList.toggle('hidden', isLocked); // .hidden es !important en CSS

    setupMaster.classList.toggle('hidden', security.crypto);
    liveMaster.classList.toggle('hidden', !security.crypto);
    if (security.crypto && security.unlocked) {
      masterState.textContent =
        'Vault descifrado en RAM (sin llave en disco). Auto-bloqueo a los ' +
        Math.round((security.ttlMs || 0) / 60000) + ' min de inactividad.';
    } else if (security.crypto) {
      masterState.textContent = 'No verás más que esto hasta desbloquear.';
    }
  }

  /** Pregunta el estado al SW + pinta la UI. (El arranque usa vault:boot: 1 ronda.) */
  async function refreshSecurity() {
    const st = await sendMsg({ type: 'vault:status' });
    security = (st && st.ok) ? st : { crypto: false, unlocked: false, ttlMs: 0 };
    applySecurityUi();
  }

  unlockForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const res = await sendMsg({ type: 'vault:unlock', password: unlockPass.value });
    if (res && res.ok) {
      lockError.classList.add('hidden');
      unlockPass.value = '';
      await refreshSecurity();
      listFetched = false;
      await refreshLists();
      showToast('Almacén desbloqueado');
    } else {
      lockError.textContent = (res && res.error) || 'Contraseña incorrecta';
      lockError.classList.remove('hidden');
    }
  });

  $('#btn-lock').addEventListener('click', async () => {
    await sendMsg({ type: 'vault:lock' });
    await refreshSecurity();
    showToast('Almacén bloqueado');
  });

  $('#btn-enable-master').addEventListener('click', async () => {
    const p1 = $('#m-pass1').value, p2 = $('#m-pass2').value;
    if (p1.length < 8) { showToast('Mínimo 8 caracteres'); return; }
    if (p1 !== p2) { showToast('Las contraseñas no coinciden'); return; }
    const res = await sendMsg({ type: 'vault:enable-master', password: p1 });
    if (res && res.ok) {
      $('#m-pass1').value = $('#m-pass2').value = '';
      await refreshSecurity();
      listFetched = false;
      await refreshLists();
      showToast(`Cifrado activado · ${res.count || 0} entradas protegidas`);
    } else {
      showToast((res && res.error) || 'No se pudo activar');
    }
  });

  $('#btn-disable-master').addEventListener('click', async () => {
    const p = $('#m-disable').value;
    if (!p) { showToast('Introduce la contraseña maestra'); return; }
    const res = await sendMsg({ type: 'vault:disable-master', password: p });
    if (res && res.ok) {
      $('#m-disable').value = '';
      await refreshSecurity();
      listFetched = false;
      await refreshLists();
      showToast('Cifrado desactivado');
    } else {
      showToast((res && res.error) || 'Contraseña incorrecta');
    }
  });

  // ------------------------------------------------------------------ recuperación de huérfanas

  function showRecoverError(text) {
    recoverError.textContent = text;
    recoverError.classList.remove('hidden');
  }

  /**
   * Rescate de entradas enc:true sin config de maestra utilizable. Cada blob
   * trae su PROPIA salt e iteraciones (encryptEntry), así que la derivación se
   * hace por blob con Master.decryptWithPassword — igual que la importación de
   * respaldos. Todo se descifra localmente en el popup: funciona incluso si el
   * service worker no responde (la causa más probable del estado huérfano).
   * Política TODO-O-NADA: si un solo blob falla la autenticación AES-GCM, la
   * contraseña es incorrecta y NO se escribe nada (no dejamos el vault a medias).
   */
  $('#btn-recover').addEventListener('click', async () => {
    const pw = recoverPass.value;
    if (!pw) { showRecoverError('Introduce la contraseña maestra'); return; }

    const vault = await Vault.load();
    const orphans = vault.entries.filter((e) => e.secret && e.secret.enc === true);
    if (!orphans.length) {
      recoverPanel.classList.add('hidden');
      return;
    }

    const plain = [];
    for (const e of orphans) {
      const decrypted = await Master.decryptWithPassword(e.secret, pw);
      if (decrypted === null) {
        showRecoverError('Contraseña incorrecta: no se descifró ninguna entrada (no se cambió nada)');
        return;
      }
      plain.push(decrypted);
    }

    orphans.forEach((e, i) => {
      e.secret = { v: Vault.SCHEMA_VERSION, enc: false, plain: plain[i] };
    });
    // Si hubiera una config colgante incompatible, fuera: el vault queda en
    // estado plaintext consistente y el usuario puede re-activar la maestra
    // desde el bloque normal "Activar cifrado".
    delete vault.crypto;
    await Vault.save(vault);

    recoverPass.value = '';
    recoverPanel.classList.add('hidden');
    recoverError.classList.add('hidden');
    showToast(`Recuperadas ${orphans.length} entradas — ya puedes copiarlas/verlas`);
    await refreshSecurity();
    listFetched = false;
    await refreshLists(true);
  });

  // Diagnóstico a demanda: checkbox del bloque Seguridad (paso 3 de la sesión).
  (async () => {
    try {
      const { debug } = await chrome.storage.local.get('debug');
      debugToggle.checked = !!debug;
    } catch {}
  })();
  debugToggle.addEventListener('change', () => {
    chrome.storage.local.set({ debug: debugToggle.checked });
    showToast(debugToggle.checked ? 'Diagnóstico ON (recarga la página)' : 'Diagnóstico OFF');
  });

  // ------------------------------------------------------------------ respaldos (export/import)

  const btnExport = $('#btn-export');
  const btnImport = $('#btn-import');
  const fileImport = $('#file-import');
  const mImportPass = $('#m-import-pass');
  const ioMsg = $('#io-msg');

  function showIoMsg(text) {
    ioMsg.textContent = text;
    ioMsg.classList.remove('hidden');
  }

  /**
   * Exporta el vault COMO ESTÁ:
   *  - con maestra → secretos cifrados en el archivo (respaldo podrías mover a otro equipo;
   *    para leerlo hace falta la maestra de este vault; incluye la config criptográfica).
   *  - sin maestra → texto plano: requiere el doble-click armado (consciente).
   */
  btnExport.addEventListener('click', async () => {
    const vault = await Vault.load();
    const isEnc = !!Vault.cryptoOf(vault);
    if (!isEnc && btnExport.dataset.armed !== '1') {
      btnExport.dataset.armed = '1';
      btnExport.classList.add('danger');
      showToast('⚠ sin cifrar: pulsa de nuevo para confirmar');
      setTimeout(() => {
        btnExport.dataset.armed = '';
        btnExport.classList.remove('danger');
      }, 3000);
      return;
    }
    const payload = {
      app: 'LocalPass',
      format: 'localpass-backup-1',
      exportedAt: new Date().toISOString(),
      crypto: vault.crypto || null,
      entries: vault.entries.map(({
        hostname, origin, origins, username, createdAt, updatedAt, secret,
      }) => ({ hostname, origin, origins, username, createdAt, updatedAt, secret })),
    };
    const blobFile = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blobFile);
    a.download = `localpass-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    showToast(isEnc ? 'Respaldo cifrado exportado' : 'Respaldo (plano) exportado');
  });

  btnImport.addEventListener('click', () => fileImport.click());

  fileImport.addEventListener('change', async () => {
    const file = fileImport.files && fileImport.files[0];
    if (!file) return;
    try {
      const data = JSON.parse(await file.text());
      if (data.app !== 'LocalPass' || !Array.isArray(data.entries)) {
        throw new Error('formato no reconocido');
      }
      const anyEnc = data.entries.some((e) => e && e.secret && e.secret.enc === true);
      if (anyEnc && !mImportPass.value) {
        showIoMsg('Respaldo cifrado: introduce su contraseña y vuelve a importar.');
        return;
      }
      const res = await sendMsg({
        type: 'vault:import',
        entries: data.entries,
        password: anyEnc ? mImportPass.value : '',
      });
      if (res && res.ok && res.locked) {
        showIoMsg('Vault local bloqueado: desbloquea primero para importar un respaldo cifrado');
      } else if (res && res.ok) {
        showIoMsg(`Importadas ${res.count} entradas (dedup por host+usuario)`);
        mImportPass.value = '';
        await refreshSecurity();
        listFetched = false;
        await refreshLists();
      } else {
        showIoMsg((res && res.error) || 'Importación fallida');
      }
    } catch (err) {
      showIoMsg('Respaldo inválido: ' + err.message);
    }
    fileImport.value = '';
  });

  // ------------------------------------------------------------------ alta / edición / borrado

  function startEdit(entry) {
    // Cargar la entrada en el formulario y saltar al panel de sitio.
    switchTab('site');
    fId.value = entry.id;
    fUser.value = entry.username || '';
    fPass.value = entry.password || '';
    fUser.focus();
    btnCancel.classList.remove('hidden');
  }

  function resetForm() {
    credForm.reset();
    fId.value = '';
    btnCancel.classList.add('hidden');
  }

  credForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const password = fPass.value;
    const username = fUser.value.trim();

    if (!currentHost) { showToast('Sitio actual no compatible'); return; }
    if (!password && !username) { showToast('Rellena usuario y/o contraseña'); return; }

    let savedId = null;

    if (security.crypto) {
      // Con maestra activa el cifrado del secret lo hace el SW (últle autoridad).
      const res = await sendMsg({
        type: 'vault:capture',
        data: { hostname: currentHost, username, password },
      });
      if (!res || res.ok !== true || res.locked) {
        // ANTES de este fix se borraba la entrada original y recién entonces se
        // intentaba guardar: con el vault bloqueado, la edición destruía datos.
        showToast('Vault bloqueado: no se guardó');
        return;
      }
      savedId = res.id || null;
    } else {
      const { entry } = await Vault.upsert({ hostname: currentHost, username, password });
      savedId = entry.id;
    }

    if (fId.value) {
      // --- EDICIÓN: borrar solo si el upsert CREÓ una entrada nueva (cambió el
      //     usuario). Si el dedup por (hostname + username) reutilizó la entrada
      //     original, savedId === fId.value y borrarla la destruiría.
      if (fId.value !== savedId) await Vault.remove(fId.value);
    }

    showToast(fId.value ? 'Credencial actualizada' : 'Credencial guardada');
    resetForm();
    await refreshLists(true);
  });

  btnCancel.addEventListener('click', resetForm);

  /** Elimina por id (las METADATOS no son secretos: usamos Vault local siempre). */
  async function removeEntry(entry) {
    const delBtn = allList.querySelector(`.row[data-id="${entry.id}"] .del`)
      || siteList.querySelector(`.row[data-id="${entry.id}"] .del`);
    if (delBtn && delBtn.dataset.armed !== '1') {
      delBtn.dataset.armed = '1';
      delBtn.classList.add('danger');
      setTimeout(() => {
        delBtn.dataset.armed = '';
        delBtn.classList.remove('danger');
      }, 2500);
      return;
    }
    await Vault.remove(entry.id);
    showToast('Credencial eliminada');
    await refreshLists(true);
  }

  // ------------------------------------------------------------------ misc de UI

  function switchTab(which) {
    const isSite = which === 'site';
    $('#panel-site').classList.toggle('hidden', !isSite);
    $('#panel-all').classList.toggle('hidden', isSite);
    $('#tab-site').classList.toggle('active', isSite);
    $('#tab-all').classList.toggle('active', !isSite);
    if (!isSite) refreshLists();
  }
  $('#tab-site').addEventListener('click', () => switchTab('site'));
  $('#tab-all').addEventListener('click', () => switchTab('all'));

  $('#toggle-pass').addEventListener('click', () => {
    const showing = fPass.type === 'password';
    fPass.type = showing ? 'text' : 'password';
    // Estado accesible para lectores de pantalla (el botón llega con aria-pressed en el HTML).
    $('#toggle-pass').setAttribute('aria-pressed', String(showing));
  });

  search.addEventListener('input', () => renderList(allList, filteredEntries(), true));

  /**
   * Cambios EXTERNOS al vault (p. ej. el content script guarda mientras el
   * popup está abierto) → reinvierte la caché local y re-render.
   * (Nuestros propios CRUD invalidan con refreshLists(true) ya; este listener lo
   * duplica en ligeramente — el costo es un re-render redundante, aceptable.)
   */
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && Vault.STORAGE_KEY in changes && listFetched) {
      listFetched = false;
      refreshLists();
    }
  });

  // ------------------------------------------------------------------ arranque (paralelizado)

  (async () => {
    // RENDIMIENTO: dos arranques en paralelo.
    //  - detectCurrentSite(): tabs.query (rápido, sin SW).
    //  - vault:boot: UN solo despertar del SW que trae estado de seguridad
    //    + entradas ya descifradas (siestá desbloqueado). Antes eran 3 rondas
    //    en serie: status, tabs, list — cada una con su IPC y sliding-TTL.
    const [boot] = await Promise.all([
      sendMsg({ type: 'vault:boot' }),
      detectCurrentSite(),
    ]);

    if (boot && boot.ok) {
      security = {
        crypto: !!boot.crypto,
        unlocked: !!boot.unlocked,
        ttlMs: boot.ttlMs || 0,
      };
      if (Array.isArray(boot.entries)) {
        allEntries = boot.entries;    // ya viene "plain" desde el SW
        listFetched = true;           // evita el re-fetch de refreshLists()
      }
    } else {
      await refreshSecurity();        // fallback: protocolo antiguo
    }

    applySecurityUi();                // pinta lock screen si corresponde
    if (security.crypto && !security.unlocked) return; // solo lock screen

    await refreshLists();             // no refetch: usa las entradas del boot
    // focus inicial cómodo y seguro: solo el usuario si estamos en un sitio válido
    if (currentHost) fUser.focus();
  })();
})();

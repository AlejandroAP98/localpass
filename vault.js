/**
 * vault.js — Capa de persistencia compartida.
 *
 * Este archivo se carga DOS veces:
 *   1. Como primer script de "content_scripts" (mundo aislado del content script).
 *   2. Como <script> de popup.html (contexto de la página de extensión).
 *
 * Por eso TODO el estado vive en chrome.storage.local y las funciones son asíncronas:
 * no hay variables compartidas en memoria entre ambos contextos.
 *
 * Diseño pensado para FASE 2 (cifrado AES-GCM + contraseña maestra):
 *   - El esquema ya guarda un marcador `enc` por entrada y los secretos se
 *     codifican/decodifican SOLO a través de `_encodeSecret` / `_decodeSecret`.
 *   - Cuando llegue el cifrado, `_encodeSecret` devolverá un blob cifrado
 *     (p. ej. `{v:1, iv, salt, ct}`) y `_decodeSecret` lo descifrará pidiendo
 *     la contraseña maestra al usuario. Ni content.js ni popup.js tendrán que cambiar.
 */
(() => {
  'use strict';

  const STORAGE_KEY = 'vault_v1';
  // Bump al cambiar el esquema; las migraciones se hacen en `_migrate`.
  const SCHEMA_VERSION = 1;

  // ------------------------------------------------------------------ secretos

  /**
   * FASE 2 SUSTITUIR ESTE MÉTODO PERO NO SU FIRMA NI SU USO.
   * Actualmente marca el secreto como "texto plano".
   * En fase 2 devolverá: { v: 1, enc: true, iv, salt, ct: "<base64 AES-GCM>" }.
   *
   * @param {string} password Contraseña en claro (solo vive en memoria).
   * @returns {Promise<SecretBlob>} Objeto serializable para chrome.storage.
   */
  async function _encodeSecret(password) {
    return { v: SCHEMA_VERSION, enc: false, plain: password };
  }

  /**
   * Contraparte de _encodeSecret. Único punto por donde sale una contraseña
   * del almacenamiento. En fase 2 aquí entra PBKDF2 + AES-GCM (decrypt + auth).
   *
   * @param {SecretBlob} blob
   * @returns {Promise<string>} Contraseña en claro.
   */
  async function _decodeSecret(blob) {
    if (!blob || typeof blob !== 'object') return '';
    return blob.enc ? '(cifrado: pendiente de fase 2)' : (blob.plain || '');
  }

  /** Indica si una entrada guarda su secreto cifrado (para pintar el candado en la UI). */
  function isEncrypted(entry) {
    return !!(entry && entry.secret && entry.secret.enc === true);
  }

  // ------------------------------------------------------------------ esquema

  /**
   * Crea la estructura vacía del almacén.
   * `{ v, entries: [...] }` — el prefijo de versión evita migraciones ambiguas.
   */
  function emptyVault() {
    return { entries: [] };
  }

  /** Normaliza el vault. Estructura: `{ entries: [...], crypto?: {...} }`.
   *  El cifrado de la contraseña maestra es ORTOGONAL a la forma de la
   *  estructura: al activarlo solo se añade `crypto` (config PBKDF2) y los
   *  secretos pasan a blobs `{enc:true, iv, ct}`; sin migración de versión. */
  function _migrate(raw) {
    if (!raw || typeof raw !== 'object' || !Array.isArray(raw.entries)) {
      return emptyVault();
    }
    return raw;
  }

  /** Config de cifrado del vault (null = secretos en texto plano). */
  function cryptoOf(vault) {
    return (vault && vault.crypto && vault.crypto.salt) ? vault.crypto : null;
  }

  // ------------------------------------------------------------------ idiomas de dominio

  /** Deriva un identificador estable del sitio. Ignora esquema y puerto a propósito:
   *  una voucher de router que salta de http://192.168.1.1 a :8443 sigue coincidiendo. */
  function hostnameKey(urlLike) {
    try {
      return new URL(urlLike).hostname.toLowerCase();
    } catch {
      // Si nos pasan solo el hostname sin URL válida, lo normalizamos tal cual.
      return String(urlLike || '').trim().toLowerCase();
    }
  }

  /**
   * ¿Es un destino "local" según nuestro contrato de seguridad?
   * Acepta localhost, mDNS (.local), redes IPv4 privadas/link-local y loopback.
   * Lo usan content.js y popup.js para decidir si actúan, INDEPENDIENTEMENTE del
   * esquema (http o https): un router con TLS autofirmado sigue siendo LAN.
   */
  function isLocalTarget(hostname) {
    const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, ''); // despoja corchetes IPv6
    if (!h) return false;
    if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
    if (h === '::1' || h.startsWith('fe80:') || h.startsWith('fd') || h.startsWith('fc')) return true; // loopback / link-local / ULA IPv6

    const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false; // dominio público o importables raros → NO activamos
    const a = +m[1], b = +m[2];
    const inRange = (x, lo, hi) => x >= lo && x <= hi;
    return (
      a === 127 ||                                    // loopback 127.0.0.0/8
      a === 10 ||                                     // 10.0.0.0/8
      (a === 172 && inRange(b, 16, 31)) ||            // 172.16.0.0/12
      (a === 192 && b === 168) ||                     // 192.168.0.0/16
      (a === 169 && b === 254)                        // APIPA 169.254.0.0/16
    );
  }

  /** Genera IDs sin dependencias. crypto.randomUUID existe en Chrome/Brave modernos. */
  function newId() {
    return (crypto && crypto.randomUUID)
      ? crypto.randomUUID()
      : 'id-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10);
  }

  // ------------------------------------------------------------------ I/O principal

  /**
   * Caché en memoria POR CONTEXTO (content, popup, SW): los reads de
   * chrome.storage.local son round-trips IPC que dominaban el tiempo del
   * "¿hay credenciales?" en cada scan/foco. La coherencia se mantiene con
   * storage.onChanged, que dispara en TODOS los contextos de la extensión
   * cuando cualquier capa escribe.
   *
   * ⚠ El objeto devuelto es el MISMO entre llamadas: tratarlo como READ-ONLY;
   * las mutaciones se hacen sobre copias (así lo hacen remove/upsert).
   */
  let cachedVault = null;
  if (chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && STORAGE_KEY in changes) {
        cachedVault = _migrate(changes[STORAGE_KEY].newValue);
      }
    });
  }

  /** Lee todo el vault (memoria si está caliente). Siempre válido. */
  async function load() {
    if (cachedVault) return cachedVault;
    const data = await chrome.storage.local.get(STORAGE_KEY);
    cachedVault = _migrate(data[STORAGE_KEY]);
    return cachedVault;
  }

  /** Escribe el vault completo. Único punto de escritura (y de invalidez de caché). */
  async function save(vault) {
    cachedVault = vault;
    await chrome.storage.local.set({ [STORAGE_KEY]: vault });
  }

  /** Devuelve las entradas de un hostname, más recientes primero. */
  async function findByHostname(hostname) {
    const key = hostnameKey(hostname);
    const vault = await load();
    return vault.entries
      .filter((e) => hostnameKey(e.hostname) === key)
      .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  }

  /**
   * Inserta o actualiza una entrada.
   * Dedup por (hostname + username): si ya existe, actualiza el secreto.
   * @param {object} data {hostname, origin?, username, password}
   * @param {SecretBlob} [secretBlob] secreto YA cifrado (lo pasa el service
   *        worker cuando la contraseña maestra está activa); si falta, se
   *        guarda en texto plano por la vía legacy.
   */
  async function upsert(data, secretBlob) {
    const host = hostnameKey(data.hostname);
    const user = (data.username || '').trim();
    const secret = secretBlob || await _encodeSecret(data.password || '');

    const vault = await load();
    let entry = vault.entries.find(
      (e) => hostnameKey(e.hostname) === host && (e.username || '').trim() === user
    );

    if (entry) {
      entry.secret = secret;
      // Huella de orígenes (anti-phishing LAN): un mismo host puede aparecer
      // (legítimamente) por varios orígenes; la entrada los colecciona (máx. 6)
      // para poder avisar cuando la página actual llega por una vía NUNCA vista.
      entry.origins = Array.isArray(entry.origins) ? entry.origins
        : (entry.origin ? [entry.origin] : []);
      if (data.origin && !entry.origins.includes(data.origin)) {
        entry.origins.push(data.origin);
        if (entry.origins.length > 6) entry.origins.splice(0, entry.origins.length - 6);
      }
      entry.origin = data.origin || entry.origin;
      entry.updatedAt = Date.now();
    } else {
      entry = {
        id: newId(),
        hostname: host,
        origin: data.origin || '',
        origins: data.origin ? [data.origin] : [],
        username: user,
        secret,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
      vault.entries.push(entry);
    }

    await save(vault);
    return { entry, created: !entry.updatedAt || entry.createdAt === entry.updatedAt };
  }

  /** Elimina por id. @returns {Promise<boolean>} true si existía. */
  async function remove(id) {
    const vault = await load();
    const before = vault.entries.length;
    vault.entries = vault.entries.filter((e) => e.id !== id);
    if (vault.entries.length === before) return false;
    await save(vault);
    return true;
  }

  /** Popular para UI: lista completa con secretos ya en claro.
   *  En fase 2 este es el único método que pedirá la contraseña maestra. */
  async function listPlain() {
    const vault = await load();
    return Promise.all(vault.entries.map(async (e) => ({
      ...e,
      password: await _decodeSecret(e.secret),
      encrypted: isEncrypted(e),
    })));
  }

  // ------------------------------------------------------------------ export global

  globalThis.Vault = {
    STORAGE_KEY,
    SCHEMA_VERSION,
    load,
    save,
    findByHostname,
    upsert,
    remove,
    listPlain,
    newId,
    hostnameKey,
    isLocalTarget,
    isEncrypted,
    cryptoOf,
    // Expuestos para que la fase 2 (popup de contraseña maestra) los reemplace.
    _encodeSecret,
    _decodeSecret,
  };
})();

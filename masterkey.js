/**
 * masterkey.js — Cifrado de fase 2: contraseña maestra (PBKDF2 + AES-256-GCM).
 *
 * Roles de este módulo (lo cargan el service worker Y el popup):
 *   - Derivar la llave desde la contraseña maestra: PBKDF2(SHA-256, 600k iter,
 *     salt aleatoria de 16 B) → AES-GCM 256.
 *   - Verificar la contraseña SIN almacenarla: se cifra/descifra un token
 *     constante ("bloque check") y se compara.
 *   - Mantener la llave SOLO en chrome.storage.session (RAM del navegador,
 *     no toca disco) con auto-bloqueo deslizante (10 min sin uso).
 *   - cifrar/descifrar secretos de entradas {iv, ct} base64.
 *
 * No confundir: los SECRETOS viajan cifrados por el storage; la MAESTRA nunca
 * se persiste ni siquiera en session — solo la DERIVADA, extractable por
 * necesidad del export→import (tradeoff documentado).
 */
(() => {
  'use strict';

  // ------------------------------------------------------------------ constantes

  const KDF_ITERATIONS = 600_000;      // OWASP 2023 para PBKDF2-HMAC-SHA256
  const CHECK_PLAINTEXT = '"LocalPass-master-check-v1"';
  const SESSION = { key: 'mp_key_raw', at: 'mp_unlocked_at' };
  const UNLOCK_TTL_MS = 10 * 60 * 1000; // auto-bloqueo deslizante

  // ------------------------------------------------------------------ base64 <-> Uint8Array

  function bufToB64(u8) {
    let s = '';
    for (const b of u8) s += String.fromCharCode(b);
    return btoa(s);
  }
  function b64ToU8(b64) {
    const s = atob(b64);
    const u = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  }

  // ------------------------------------------------------------------ primitivas Web Crypto

  /** PBKDF2 → CryptoKey AES-GCM (extractable para exportar a la sesión). */
  async function deriveKey(password, saltU8, iterations) {
    const base = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltU8, iterations, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      true, // extractable: export→import para guardar la derivada en storage.session
      ['encrypt', 'decrypt']);
  }

  /** AES-GCM: devuelve {iv, ct} base64 sobre un string UTF-8. */
  async function encryptStr(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(plaintext));
    return { iv: bufToB64(iv), ct: bufToB64(new Uint8Array(ct)) };
  }

  async function decryptStr(key, blob) {
    const u8 = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToU8(blob.iv) },
      key,
      b64ToU8(blob.ct));
    return new TextDecoder().decode(u8);
  }

  /** Blob de secreto de entrada: {enc:true, kdf, iterations, salt, iv, ct}. */
  async function encryptEntry(key, password, cfg) {
    return {
      enc: true, kdf: 'pbkdf2-sha256', iterations: cfg.iterations, salt: cfg.salt,
      ...(await encryptStr(key, String(password))),
    };
  }

  async function decryptEntry(key, blob) {
    return decryptStr(key, blob);
  }

  // ------------------------------------------------------------------ ciclo de vida

  /**
   * Crea la config de cifrado nueva (alta/cambio de maestra).
   * @returns {Promise<{cfg: {iterations, salt, check:{iv,ct}}, key: CryptoKey}>}
   */
  async function buildConfig(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt, KDF_ITERATIONS);
    const check = await encryptStr(key, CHECK_PLAINTEXT);
    return { cfg: { iterations: KDF_ITERATIONS, salt: bufToB64(salt), check }, key };
  }

  /** Verifica la maestra contra el bloque check. @returns {CryptoKey|null} */
  async function verifyPassword(password, cfg) {
    try {
      const salt = b64ToU8(cfg.salt);
      const key = await deriveKey(password, salt, cfg.iterations);
      const plain = await decryptStr(key, cfg.check);
      return plain === CHECK_PLAINTEXT ? key : null;
    } catch {
      return null; // AES-GCM falla (auth) → contraseña equivocada
    }
  }

  /**
   * Descifra un blob de respaldo con SU contraseña (puede ser distinta de la
   * maestra local): usa la salt/iteraciones que trae el propio blob. Autorización
   * errónea AES-GCM → desarga → `null`.
   */
  async function decryptWithPassword(blob, password) {
    try {
      const salt = b64ToU8(blob.salt);
      const key = await deriveKey(password, salt, blob.iterations || KDF_ITERATIONS);
      return await decryptStr(key, blob);
    } catch {
      return null;
    }
  }

  // ------------------------------------------------------------------ llave en sesión (RAM)

  /** Persiste la LLAVE DERIVADA en storage.session (RAM, no disco). */
  async function storeSessionKey(key) {
    const raw = await crypto.subtle.exportKey('raw', key);
    await chrome.storage.session.set({
      [SESSION.key]: bufToB64(new Uint8Array(raw)),
      [SESSION.at]: Date.now(),
    });
  }

  /**
   * Llave de sesión vigente (o null). Aplica el TTL deslizante: cada consulta
   * renewa el timestamp, de modo que "10 min SIN USO" es el criterio real.
   */
  async function getSessionKey() {
    const data = await chrome.storage.session.get([SESSION.key, SESSION.at]);
    if (!data[SESSION.key]) return null;
    const at = data[SESSION.at] || 0;
    if (Date.now() - at > UNLOCK_TTL_MS) {
      await chrome.storage.session.remove([SESSION.key, SESSION.at]);
      return null;
    }
    await chrome.storage.session.set({ [SESSION.at]: Date.now() }); // sliding
    const raw = b64ToU8(data[SESSION.key]);
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  }

  /** Bloqueo explícito (botón o TTL). */
  async function lock() {
    await chrome.storage.session.remove([SESSION.key, SESSION.at]);
  }

  // ------------------------------------------------------------------ export

  globalThis.Master = {
    KDF_ITERATIONS,
    UNLOCK_TTL_MS,
    buildConfig,
    verifyPassword,
    decryptWithPassword,
    encryptEntry,
    decryptEntry,
    storeSessionKey,
    getSessionKey,
    lock,
  };
})();

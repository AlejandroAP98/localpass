/**
 * background.js — Service worker MV3: autoridad de seguridad de LocalPass.
 *
 * Responsabilidades:
 *   1. Badge "✓" al guardar (feedback sin abrir popup).
 *   2. NÚCLEO DEL CIFRADO (fase 2): cuando la contraseña maestra está activa,
 *      TODO descifrado/captura pasa por aquí — única capa con acceso a la llave
 *      derivada (vive en chrome.storage.session = RAM, auto-bloqueo 10 min).
 *
 * Protocolo de mensajes (todos responden {ok[, ...]}):
 *   vault:status         → {crypto, unlocked}
 *   vault:unlock {pw}    → verifica maestra y almacena la derivada en sesión
 *   vault:lock           → purga la llave de sesión
 *   vault:list           → {entries} con password en claro (o {locked:true})
 *   vault:capture {data} → guarda/actualiza entrada cifrada (o {locked:true})
 *   vault:decrypt {blob} → {password} para el fill del content script
 *   vault:enable-master {pw}  → alta: re-cifra TODAS las entradas existentes
 *   vault:disable-master {pw} → baja: descifra todo y borra la config
 */
importScripts('vault.js');
importScripts('masterkey.js');

// ------------------------------------------------------------------ badge

const BADGE_TEXT = '✓';
const BADGE_BG = '#2da44e';
const BADGE_MS = 3000;
function flashBadge() {
  chrome.action.setBadgeBackgroundColor({ color: BADGE_BG });
  chrome.action.setBadgeText({ text: BADGE_TEXT });
  setTimeout(() => chrome.action.setBadgeText({ text: '' }), BADGE_MS);
}

// ------------------------------------------------------------------ decodificación de secretos

/** Secreto de entrada → password en claro ('' si falta llave/blob corrupto). */
async function decodeSecret(blob, key) {
  if (!blob) return '';
  if (blob.enc !== true) return blob.plain || ''; // texto plano legacy (sin maestra)
  if (!key) return '';
  try {
    return await Master.decryptEntry(key, blob);
  } catch {
    return '(error al descifrar)';
  }
}

/** Llave vigente o null si hay cifrado pero el vault está bloqueado. */
async function sessionKeyFor(vault) {
  const cfg = Vault.cryptoOf(vault);
  if (!cfg) return { key: null, cfg: null };
  const key = await Master.getSessionKey();
  return { key, cfg };
}

// ------------------------------------------------------------------ router de mensajes

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  handle(msg).then(sendResponse).catch((err) => {
    sendResponse({ ok: false, error: String((err && err.message) || err) });
  });
  return true; // canal asíncrono abierto hasta que sendResponse dispare
});

async function handle(msg) {
  if (!msg || typeof msg.type !== 'string') {
    return { ok: false, error: 'mensaje inválido' };
  }

  switch (msg.type) {
    case 'vault:saved':
      flashBadge();
      return { ok: true };

    case 'vault:status': {
      const vault = await Vault.load();
      return {
        ok: true,
        crypto: !!Vault.cryptoOf(vault),
        unlocked: !!(await Master.getSessionKey()),
        ttlMs: Master.UNLOCK_TTL_MS,
      };
    }

    /**
     * vault:boot — RENDIMIENTO: status + lista de entradas en UN solo despertar
     * del SW. Antes el popup hacía status → list (dos rodadas IPC + dos toques
     * de storage.session por el sliding-TTL). Cuando el vault está bloqueado
     * NO devuelve entries (y la UI pinta el lock screen igual).
     */
    case 'vault:boot': {
      const vault = await Vault.load();
      const cfg = Vault.cryptoOf(vault);
      const key = cfg ? await Master.getSessionKey() : null;
      const unlocked = !cfg ? true : !!key;
      let entries;
      if (unlocked) {
        entries = await Promise.all(vault.entries.map(async (e) => ({
          ...e,
          password: await decodeSecret(e.secret, key),
          encrypted: Vault.isEncrypted(e),
        })));
      }
      return { ok: true, crypto: !!cfg, unlocked, ttlMs: Master.UNLOCK_TTL_MS, entries };
    }

    case 'vault:unlock': {
      const vault = await Vault.load();
      const cfg = Vault.cryptoOf(vault);
      if (!cfg) return { ok: false, error: 'cifrado no activo' };
      const key = await Master.verifyPassword(String(msg.password || ''), cfg);
      if (!key) return { ok: false, error: 'Contraseña maestra incorrecta' };
      await Master.storeSessionKey(key);
      return { ok: true };
    }

    case 'vault:lock':
      await Master.lock();
      return { ok: true };

    case 'vault:list': {
      const vault = await Vault.load();
      const { key } = await sessionKeyFor(vault);
      if (Vault.cryptoOf(vault) && !key) return { ok: true, locked: true };
      const entries = await Promise.all(vault.entries.map(async (e) => ({
        ...e,
        password: await decodeSecret(e.secret, key),
        encrypted: Vault.isEncrypted(e),
      })));
      return { ok: true, entries };
    }

    case 'vault:capture': {
      const d = msg.data || {};
      if (!d.hostname || typeof d.password !== 'string') {
        return { ok: false, error: 'datos incompletos' };
      }
      const vault = await Vault.load();
      const cfg = Vault.cryptoOf(vault);
      if (cfg) {
        const key = await Master.getSessionKey();
        if (!key) return { ok: true, locked: true };
        // Dedup por (host+usuario) lo hace Vault.upsert; el secreto ya viene cifrado.
        // Devolvemos el id para que el popup sepa si el upsert REUTILIZÓ la
        // entrada original (edición con mismo host+usuario) o creó una nueva.
        const saved = await Vault.upsert(d, await Master.encryptEntry(key, d.password, cfg));
        return { ok: true, id: saved.entry.id };
      } else {
        const saved = await Vault.upsert(d); // vía legacy en texto plano
        return { ok: true, id: saved.entry.id };
      }
    }

    case 'vault:decrypt': {
      const vault = await Vault.load();
      const { key } = await sessionKeyFor(vault);
      const cfg = Vault.cryptoOf(vault);
      if (cfg && !key) return { ok: true, locked: true };
      return { ok: true, password: await decodeSecret(msg.blob, key) };
    }

    case 'vault:enable-master': {
      const pw = String(msg.password || '');
      if (pw.length < 8) return { ok: false, error: 'Mínimo 8 caracteres' };
      const { cfg, key } = await Master.buildConfig(pw);

      // Re-cifrado EN LOTE de todo el vault existente (migración local, atómica).
      const vault = await Vault.load();
      vault.entries = await Promise.all(vault.entries.map(async (e) => ({
        ...e,
        secret: await Master.encryptEntry(key, await decodeSecret(e.secret, null), cfg),
      })));
      vault.crypto = cfg;
      await Vault.save(vault);
      await Master.storeSessionKey(key);
      return { ok: true, count: vault.entries.length, iterations: cfg.iterations };
    }

    case 'vault:disable-master': {
      const vault = await Vault.load();
      const cfg = Vault.cryptoOf(vault);
      if (!cfg) return { ok: false, error: 'cifrado no activo' };
      const key = await Master.verifyPassword(String(msg.password || ''), cfg);
      if (!key) return { ok: false, error: 'Contraseña maestra incorrecta' };

      // Descifrado en lote → vuelve al esquema plaintext (sin llave en memoria).
      vault.entries = await Promise.all(vault.entries.map(async (e) => ({
        ...e,
        secret: { v: 1, enc: false, plain: await decodeSecret(e.secret, key) },
      })));
      delete vault.crypto;
      await Vault.save(vault);
      await Master.lock();
      return { ok: true, count: vault.entries.length };
    }

    case 'vault:import': {
      const incoming = Array.isArray(msg.entries)
        ? msg.entries.filter((e) => e && typeof e === 'object'
            && typeof e.hostname === 'string' && e.secret)
        : [];
      if (!incoming.length) return { ok: false, error: 'respaldo sin entradas válidas' };

      // Cada entrada del respaldo → password en claro:
      //  - enc:true  → se descifra con la CONTRASEÑA DEL RESPALDO (salt propia del blob)
      //  - enc:false → ya es texto plano
      let items = [];
      if (incoming.some((e) => e.secret.enc === true)) {
        const pw = String(msg.password || '');
        if (!pw) return { ok: false, error: 'Respaldo cifrado: falta su contraseña' };
        items = [];
        for (const e of incoming) {
          let password;
          if (e.secret.enc === true) {
            password = await Master.decryptWithPassword(e.secret, pw);
            if (password === null) {
              return { ok: false, error: 'Contraseña del respaldo incorrecta' };
            }
          } else {
            password = e.secret.plain || '';
          }
          items.push({ hostname: e.hostname, origin: e.origin, username: e.username, password });
        }
      } else {
        items = incoming.map((e) => ({
          hostname: e.hostname, origin: e.origin,
          username: e.username, password: e.secret.plain || '',
        }));
      }

      // Upsert con la config LOCAL (cifra si el vault local ya tiene maestra).
      const vault = await Vault.load();
      const cfg = Vault.cryptoOf(vault);
      if (cfg) {
        const key = await Master.getSessionKey();
        if (!key) return { ok: true, locked: true };
        let count = 0;
        for (const item of items) {
          await Vault.upsert(item, await Master.encryptEntry(key, item.password, cfg));
          count++;
        }
        return { ok: true, count };
      }
      let count = 0;
      for (const item of items) {
        await Vault.upsert(item);
        count++;
      }
      return { ok: true, count };
    }

    default:
      return { ok: false, error: 'tipo desconocido: ' + msg.type };
  }
}

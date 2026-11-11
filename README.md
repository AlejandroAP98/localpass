# LocalPass — Autocompletado HTTP local (Brave / Chrome, MV3)

Gestor de credenciales 100% **local** para destinos LAN/in-local: routers, servidores
de desarrollo, IPs internas (`localhost`, `192.168.x.x`, `10.x.x.x`...), **con o sin
TLS** (incluye HTTPS con certificado autofirmado tipo `https://10.167.4.162`).
Sin cuentas, sin sincronización, sin telemetría. Los datos viven únicamente en
`chrome.storage.local` del navegador, filtrados por permisos y una guarda en runtime
(`Vault.isLocalTarget`) que desactiva todo en dominios públicos.

## Instalación en Brave (o Chrome/Edge)

1. `brave://extensions` → activa **Modo de desarrollador** (esquina superior derecha).
2. **Cargar extensión sin empaquetar** → selecciona esta carpeta.
3. Opcional: fija el icono en la barra de herramientas.
4. No requiere "Acceso a archivos de URL". Al cubrir `https://*/*` Brave mostrará
   el aviso de "leer y cambiar datos en todos los sitios": es inevitable porque los
   match patterns no admiten comodines de IP; la restricción real a hosts privados
   la aplica `Vault.isLocalTarget` en runtime. Si prefieres el aviso mínimo,
   sustituye `https://*/*` por entradas explícitas (p. ej. `https://10.167.4.162/*`).

## Componentes

| Archivo       | Rol |
|---------------|-----|
| `manifest.json` | MV3: `storage`, `clipboardWrite`, host http+https, SW `background.js`, iconos |
| `vault.js`      | Capa de persistencia compartida (`{entries, crypto?}`): local o cifrada, misma API |
| `masterkey.js`  | Fase 2: PBKDF2(SHA-256, 600k) → AES-256-GCM. Llave solo en `chrome.storage.session` (RAM, auto-bloqueo 10 min) |
| `content.js`    | Detección dinámica, autocompletado SPA/two-step, captura, selector in-page para ≥2 credenciales |
| `inject_main.js` | Script en **mundo MAIN** (`document_start`): intercepta `attachShadow({mode:"closed"})` y rellena inputs inalcanzables para el mundo aislado |
| `content.css`   | Toast in-page |
| `background.js` | SW: badge `✓` + **autoridad del cifrado** (unlock/lock/decrypt/capture/enable/disable vía mensajes) |
| `icons/`        | SVG fuente + PNG 16/48/128 (generados) |
| `popup.html/css/js` | CRUD de credenciales: sitio actual / todas, buscar, copiar (autolimpieza 20 s) |

## Comportamiento

- **Autocompletado**: con exactamente 1 credencial para el dominio, rellena
  automáticamente usuario+password (respetando lo que ya escribiste). Con varias,
  haz match tecleando tu usuario. Soporta **login en dos pasos** (pantalla de
  usuario → pantalla de contraseña), Shadow DOM "closed" vía mundo MAIN y el
  re-intento por foco (click en el campo) cuando el JS del sitio limpia campos.
- **Guardado**: se captura al hacer `submit` (fase de captura) o al pulsar un botón
  tipo login en formularios **sin `<form>`** (firmware de routers). Dedup por
  `(host + usuario)`.
- **Compatibilidad frameworks**: el autocompletado escribe el value con el setter
  nativo del prototipo `HTMLInputElement` y dispara `input` + `change` burbujeantes,
  de modo que React/Vue/Angular detectan el cambio.

## Probar rápido

1. Crea un `test.html` local con `<input name="user">` + `<input type="password">`
   y `http-server` o `python -m http.server`; ábrelo vía `http://localhost:PORT`.
2. Rellena usuario/contraseña y envía → badge `✓` + toast.
3. Recarga el `test.html`: debe autorrellenarse.

## Seguridad (contraseña maestra, fase 2)

1. popup → pestaña "Todas" → **Seguridad** → escribe una maestra (mín. 8) → "Activar cifrado".
   Re-cifra en lote todo lo existente (PBKDF2 600k + AES-256-GCM).
2. Desde ese momento: llave derivada SOLO en `chrome.storage.session` (RAM —
   sobrevive a recargas de página, muere al cerrar el navegador). Auto-bloqueo
   deslizante a los 10 min sin uso; botón "🔒 Bloquear ahora".
3. Con el vault bloqueado: ni relleno ni guardado; el popup muestra su pantalla de desbloqueo.
4. "Desactivar cifrado" requiere la maestra y descifra todo en lote.
5. **Si olvidas la maestra, los datos no se recuperan** (es la propiedad buscada).

Diagnóstico: checkbox "Diagnóstico" en Seguridad → activa los logs
`[LocalPass]` (console.debug) en las páginas locales.

## Respaldos (export/import JSON)

- **Exportar** (Seguridad → ⬇): si hay maestra, el archivo lleva los secretos
  cifrados (AES-GCM) — legibles solo con la maestra de ese vault. Sin maestra,
  el respaldo es texto plano (export con doble-click de confirmación).
- **Importar** (⬆): dedup por `(host + usuario)`. Respaldo cifrado → pide la
  contraseña con la que se generó (puede ser distinta de la maestra local) y
  se re-encripta con la config local si el vault local tiene maestra.

## Huella de origen (anti-phishing LAN)

Cada entrada colecciona los orígenes (`http/https + puerto`) por los que se
guardó (máx. 6). Si la página actual usa un origen nunca registrado:
- aviso in-page una vez por carga, y
- badge ⚠ en la fila (popup) con el detalle en tooltip.
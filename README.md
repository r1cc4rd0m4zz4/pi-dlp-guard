# pi-dlp-guard 🛡️

```text
          _           _ _                                    _ 
 _ __ (_)       __| | |_ __         __ _ _   _  __ _ _ __  __| |
| '_ \| | _____ / _` | | '_ \ _____ / _` | | | |/ _` | '__|/ _` |
| |_) | ||_____| (_| | | |_) |_____| (_| | |_| | (_| | |  | (_| |
| .__/|_|       \__,_|_| .__/       \__, |\__,_|\__,_|_|   \__,_|
|_|                    |_|          |___/                        
```

> **Zero-dependency path protection & secret redaction guard for [Pi Coding Agent](https://github.com/earendil-works/pi).**

[![Pi Package](https://img.shields.io/badge/Pi--Package-Extension-76B900?logo=github&logoColor=white)](https://github.com/r1cc4rd0m4zz4/pi-dlp-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-555555.svg)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(zero%20npm)-brightgreen.svg)

```bash
# ⚡ Install into Pi via Git:
pi install git:github.com/r1cc4rd0m4zz4/pi-dlp-guard
```

---

## Modello di Sicurezza

`pi-dlp-guard` agisce come **difesa in profondità a livello di estensione** per ridurre il rischio di esfiltrazione accidentale di credenziali e proteggere l'integrità della configurazione dell'agente.

> **Nota architetturale**: L'analisi lessicale dei comandi shell non costituisce un confine di sicurezza invalicabile contro un attaccante determinato che usa interpreti secondari, offuscamenti avanzati o chiamate dirette a basso livello. Per un isolamento ermetico dei processi dell'agente, abbina questa estensione a una sandbox a livello di kernel OS (Apple Seatbelt su macOS o Bubblewrap su Linux, es. `mysafe-run`).

### Tre Livelli di Difesa

1. **Protezione dei Percorsi nei Tool Strutturati (`tool_call`)**:
   - Blocca le operazioni di lettura e scrittura su percorsi sensibili (`.env*`, `~/.ssh/**`, `~/.aws/**`, `~/.gnupg/**`, `~/.zshrc*`, `~/.bashrc*`, `~/.pi/agent/auth.json`, chiavi private `*.pem`, `*.key`).
   - I template comuni come `.env.example` e `.env.sample` rimangono accessibili.
   - Riconosce i campi percorso su tutti i tool (non solo `read`/`write`, ma anche `read_symbol`, `ast_grep_search`, tool MCP con `path`/`paths`).
   - Risoluzione canonica (`realpath`) per neutralizzare directory traversal (`../../`) e symlink (inclusi symlink dangling).

2. **Ispezione delle Scritture Shell (`bash`)**:
   - Analizza la riga di comando scomponendo sequenze e catene (`&&`, `||`, `;`, `|`, `&`, newline).
   - Traccia i cambi di directory (`cd`, `pushd`) lungo la catena per valutare i percorsi relativi nel contesto corretto.
   - Blocca comandi mutatori (`rm`, `mv`, `cp`, `ln`, `install`, `rsync`, `touch`, `truncate`, `sed -i`, ecc.) e redirezioni di scrittura (`>`, `>>`, `| tee`) verso percorsi protetti o file di integrità dell'agente.
   - Le letture passive e le ricerche nel codice (es. `grep -rn "\.env" src/`) non vengono bloccate, delegando la protezione dell'output al livello di mascheramento.

3. **Integrità del Guardiano (Anti-Tampering)**:
   - I file di configurazione (`~/.pi/agent/**`) e la cartella stessa del pacchetto `pi-dlp-guard` sono protetti in scrittura/cancellazione dall'agente.
   - La lettura della configurazione è consentita per il normale funzionamento di Pi, ma la mutazione è riservata all'operatore umano.

4. **Mascheramento Deterministico dei Segreti (`tool_result` & `context`)**:
   - Sostituzione irreversibile dei segreti con token stabili: `[REDACTED_AWS_KEY_#1]`, `[REDACTED_GITHUB_TOKEN_#1]`, `[REDACTED_API_KEY_#1]`, `[REDACTED_PRIVATE_KEY_#1]`, `[REDACTED_SECRET_#1]`.
   - **Preservazione Relazionale**: la stessa credenziale riceve sempre lo stesso identificatore durante la sessione, permettendo al modello di comprenderne le relazioni logiche senza accedere al valore in chiaro.
   - **Idempotenza**: i segnaposto già mascherati non vengono ri-mascherati.
   - **Zero Latency Wire**: nell'hook `context` (inviato prima di ogni chiamata LLM) l'analisi opera esclusivamente tramite regex native (< 2ms per messaggi di grandi dimensioni), evitando ritardi nei turni di conversazione.
   - **Supporto Gitleaks**: sui buffer di output dei comandi (`tool_result`) superiori alla soglia configurata (default 4KB), può intervenire `gitleaks stdin` come rete di sicurezza aggiuntiva per pattern non catalogati.

---

## Comandi Interattivi Slash (`/dlp`)

| Comando | Descrizione |
|---|---|
| `/dlp` o `/dlp status` | Mostra lo stato corrente (ATTIVO/DISATTIVATO), disponibilità di Gitleaks, numero di segreti mascherati in sessione e percorsi protetti |
| `/dlp off` | Disattiva temporaneamente i controlli per la sessione corrente |
| `/dlp on` | Riattiva i controlli DLP |
| `/dlp reload` | Ricarica la configurazione da `~/.pi/agent/dlp-guard.json` senza riavviare la sessione |

---

## Configurazione (`~/.pi/agent/dlp-guard.json`)

Il file viene creato automaticamente al primo avvio se assente ed è completamente personalizzabile:

```json
{
  "protectedPaths": [
    ".env",
    ".env.*",
    "**/.git/**",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.netrc",
    "~/.zshrc*",
    "~/.bashrc*",
    "~/.bash_profile",
    "~/.profile",
    "**/*rc.local",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa*",
    "**/id_ed25519*",
    "~/.pi/agent/auth.json"
  ],
  "integrityPaths": [
    "~/.pi/agent/**"
  ],
  "enableGitleaks": true,
  "gitleaksMinBytes": 4096,
  "gitleaksTimeoutMs": 500
}
```

---

## Verifica e Test (`npm test`)

La suite di regressione copre **28 asserzioni** eseguibili in modo isolato (usando directory temporanee):

```bash
npm test
```

```text
path guard
  ok   .env variants are protected, templates are not
  ok   credentials, keys and shell rc files
  ok   benign files are not protected
  ok   cwd-relative patterns only match under cwd
  ok   symlink to a built-in protected file
  ok   symlink to a configured protected file
  ok   dangling symlink into an integrity path is blocked for write
  ok   integrity paths: read allowed, write blocked
  ok   the package's own directory is write-protected
bash guard
  ok   redirects and tee to protected paths
  ok   mutating commands, including ones missing from the first version
  ok   chained and sequential commands
  ok   cd is tracked across a chain
  ok   nested code: sh -c, eval, $(), backticks
  ok   quote splitting does not hide the target
  ok   reads, searches and ordinary commands pass
redaction
  ok   known token formats
  ok   NAME=value forms, including bare PASSWORD/TOKEN/SECRET and JSON
  ok   the same secret keeps the same token, different secrets differ
  ok   redaction is idempotent: placeholders are never re-redacted
  ok   no false positives
gitleaks
  ok   safety net catches formats the regexes do not know (large buffers only)
  ok   regexes keep working when gitleaks is disabled
extension hooks
  ok   tool_call blocks structured tools by path and operation
  ok   tool_call blocks chained bash and lets normal bash through
  ok   tool_result redacts text parts and leaves clean output untouched
  ok   context redacts string and array content, returns undefined when clean
  ok   /dlp off disables every hook, /dlp on restores them

28 passed, 0 failed
```

---

## Installazione Locale

Per collegare il repository locale nel proprio ambiente Pi:

```bash
pi install /path/to/pi-dlp-guard
```

---

## License

MIT © 2026

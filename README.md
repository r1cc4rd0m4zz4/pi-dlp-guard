# pi-dlp-guard 🛡️

```text
          _           _ _                                    _ 
 _ __ (_)       __| | |_ __         __ _ _   _  __ _ _ __  __| |
| '_ \| | _____ / _` | | '_ \ _____ / _` | | | |/ _` | '__|/ _` |
| |_) | ||_____| (_| | | |_) |_____| (_| | |_| | (_| | |  | (_| |
| .__/|_|       \__,_|_| .__/       \__, |\__,_|\__,_|_|   \__,_|
|_|                    |_|          |___/                        
```

> **Zero-dependency DLP, Path Protection, Deep Shell Obfuscation Guard & Secret Redaction for [Pi Coding Agent](https://github.com/earendil-works/pi).**

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

`pi-dlp-guard` agisce come **difesa in profondità a livello di estensione** su tutti gli hook del ciclo di vita di Pi (`tool_call`, `tool_result`, `context`) per bloccare preventivamente l'accesso a percorsi sensibili, neutralizzare l'esfiltrazione o la scrittura di segreti in chiaro, impedire la manomissione della configurazione dell'agente e mascherare in modo relazionale qualsiasi credenziale negli output.

> **Nota architetturale**: L'analisi lessicale dei comandi shell è progettata contro offuscamenti, catene e interpreti inline, ma non sostituisce l'isolamento a livello di kernel. Per un confine ermetico a livello di sistema operativo, abbina questa estensione a una sandbox OS (Apple Seatbelt su macOS o Bubblewrap su Linux).

### Quattro Livelli di Difesa

1. **Protezione Canonica dei Percorsi e Anti-Bypass (`tool_call`)**:
   - Blocca lettura, scrittura, modifica e cancellazione su oltre **60 pattern sensibili**:
     - **Segreti Ambiente**: `.env`, `.env.*`, `*.env`, `.envrc` *(consentendo i soli template `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.schema` non-symlink e fuori dai percorsi di integrità)*.
     - **Chiavi Crittografiche e Certificati**: `~/.ssh/**`, `/etc/ssh/**`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.pkcs12`, `*.jks`, `*.keystore`, `*.age`, `~/.gnupg/**`.
     - **Credenziali Cloud, Infra e Package Manager**: `~/.aws/**`, `~/.config/gcloud/**`, `~/.gcp/**`, `~/.azure/**`, `~/.oci/**`, `~/.kube/**`, `~/.docker/config.json`, `*.tfstate*`, `*.tfvars`, `~/.vault-token`, `~/.password-store/**`, `~/.config/op/**`, `~/.config/gh/**`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.pi/agent/auth.json`, `~/.claude/.credentials.json`, `/etc/shadow*`, `/etc/sudoers*`.
   - **Normalizzazione Anti-Evasione**:
     - Rilevamento null-byte injection (`\0` e `%00`)
     - Decodifica URL singola e doppia (`%2e%2e%2f`, `%252e%252e%252f`)
     - Espansione `~`, `$HOME`, `${HOME}`, `~+`, `$PWD`, `${PWD}`
     - Espansione ricorsiva di brace shell (`.{env,bak}`, `~/{.ssh,.aws}/id_rsa`)
     - Espansione wildcard (`.en?`, `.e*`, `[.]env`) sia sul filesystem reale sia sui nomi canonici sensibili
     - Risoluzione `realpath` di symlink (inclusi symlink dangling e finti `.env.example -> .env`).

2. **Ispezione Profonda Shell & Motore Anti-Offuscamento (`bash` / `run_command`)**:
   - Scompone catene e subshell (`&&`, `||`, `;`, `|`, `&`, newline, `( ... )`, `{ ...; }`, `<(...)`, `>(...)`, `$(...)` bilanciati, `` `...` ``, `sh -c`, `eval`).
   - Traccia i cambi di directory (`cd`, `pushd`) e le assegnazioni di variabili cross-segmento (`A=.e; B=nv; cat $A$B`, `export TARGET=...`).
   - Decodifica stringhe ANSI-C (`$'\x2e\x65\x6e\x76'`, `$'\056env'`), quote splitting (`.e''nv`), sostituzioni comando (`$(echo .env)`, `$(printf '%s' .env)`) ed espansioni parametro (`.${empty}env`, `${unset:-.env}`).
   - Scompatta wrapper con argomenti (`sudo -u root`, `env -i`, `timeout 5`, `nice -n 10`, `nohup`, `command`, `xargs`), traccia pipeline `echo .env | xargs ...` e blocca l'esecuzione di payload codificati (`base64 -d | sh`, `xxd -r | bash`).
   - Blocca **scritture e mutazioni** (`rm`, `mv`, `cp`, `ln`, `rsync`, `truncate`, `chmod`, `chown`, `tee`, `dd of=`, `find -delete`, `sed -i`, redirezioni `>`, `>>`, `>|`, `&>`, `<>`), **letture dirette o indirette** (`cat`, `head`, `tail`, `base64`, `xxd`, `source`, `.`, `grep`, `rg`, `sed`, `awk`, `jq`, `find`, `git show HEAD:.env`, `git diff --no-index`, `tar`, `zip`, `dd if=`, `openssl`, `< .env`), **esfiltrazioni di rete** (`curl -d @.env`, `wget --post-file`, `scp`, `sftp`) e **one-liner di interpreti** (`python -c`, `node -e`, `ruby -e`, `perl -e`).

3. **Integrità del Guardiano & Prevenzione Leak Outbound (`tool_call`)**:
   - **Anti-Tampering**: protegge in scrittura `~/.pi/agent/**`, `.pi/**`, `~/.gemini/**`, `.agents/**`, `**/dlp-guard.json` e la directory stessa di `pi-dlp-guard`. Blocca in `bash` i comandi di disattivazione/rimozione (`pi uninstall pi-dlp-guard`, `agy-dlp toggle off`).
   - **Zero-Trust sulle Configurazioni Workspace**: i file `.pi/dlp-guard.json` o `.agents/dlp-guard.json` presenti in un repository possono solo *aggiungere* percorsi protetti, mai disattivare il guardiano (`enabled: false`) né rimuovere le protezioni predefinite.
   - **Prevenzione Segreti in Scrittura ed Esfiltrazione**: blocca `write`/`edit`/`replace`/`patch` se il nuovo testo introdotto contiene segreti in chiaro, blocca i comandi `bash` con credenziali inline, e blocca query esterne (`search_web`, `fetch`, `mcp:*`) contenenti segreti.

4. **Mascheramento Deterministico Relazionale (`tool_result` & `context`)**:
   - **13 Categorie Regex Native ad Alta Precisione** (oltre 30 formati: `PRIVATE_KEY`, `AGE_SECRET_KEY`, `AWS_KEY`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `SLACK_TOKEN`, `NPM_TOKEN`, `PYPI_TOKEN`, `API_KEY` per Anthropic/OpenAI/Google/Stripe/HuggingFace/SendGrid/DigitalOcean, `JWT_TOKEN`, `BEARER_TOKEN`, `URL_CREDENTIAL`, e assegnazioni generiche `SECRET`/`KEY`/`TOKEN`/`PASSWORD`/`PW`/`CREDENTIAL` con filtro anti-falsi positivi sul codice JS/TS).
   - **Preservazione Relazionale e Idempotenza**: la stessa credenziale riceve sempre lo stesso token `[REDACTED_<CATEGORY>_#N]` nella sessione.
   - **Rete di Sicurezza Gitleaks**: sui risultati `tool_result` ≥ `gitleaksMinBytes` (default 4KB) interviene anche `gitleaks stdin` se installato nel `PATH`, mentre `context` usa solo regex native (< 2ms) per latenza zero ad ogni turno LLM.

---

## Comandi Interattivi Slash (`/dlp`)

| Comando | Descrizione |
|---|---|
| `/dlp` o `/dlp status` | Mostra lo stato corrente (ATTIVO/DISATTIVATO), disponibilità di Gitleaks, numero di segreti mascherati in sessione e percorsi protetti |
| `/dlp off` | Disattiva temporaneamente i controlli per la sessione corrente |
| `/dlp on` | Riattiva i controlli DLP |
| `/dlp reload` | Ricarica la configurazione da `dlp-guard.json` senza riavviare la sessione |

---

## Configurazione (`~/.pi/agent/dlp-guard.json`)

Vedi [`dlp-guard.json.example`](./dlp-guard.json.example) per l'elenco completo delle opzioni:

```json
{
  "enabled": true,
  "protectedPaths": [".env", ".env.*", "*.env", "~/.ssh/**", "~/.aws/**"],
  "integrityPaths": ["~/.pi/agent/**", ".pi/**", ".agents/**", "**/dlp-guard.json"],
  "enableGitleaks": true,
  "gitleaksMinBytes": 4096,
  "gitleaksTimeoutMs": 500,
  "blockInlineSecretsInCommands": true,
  "blockReaderCommandsOnProtected": true,
  "blockWriteSecrets": true
}
```

---

## Verifica e Test (`npm test`)

La suite avversariale verifica **37 gruppi di test (oltre 150 asserzioni)** in completo isolamento:

```bash
npm test
```

---

## Installazione Locale

```bash
pi install /path/to/pi-dlp-guard
```

---

## License

MIT © 2026 [r1cc4rd0m4zz4](https://github.com/r1cc4rd0m4zz4)

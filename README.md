# pi-dlp-guard 🛡️

```text
          _           _ _                                    _ 
 _ __ (_)       __| | |_ __         __ _ _   _  __ _ _ __  __| |
| '_ \| | _____ / _` | | '_ \ _____ / _` | | | |/ _` | '__|/ _` |
| |_) | ||_____| (_| | | |_) |_____| (_| | |_| | (_| | |  | (_| |
| .__/|_|       \__,_|_| .__/       \__, |\__,_|\__,_|_|   \__,_|
|_|                    |_|          |___/                        
```

> **Zero-dependency Data Loss Prevention (DLP), Path Traversal Protection & Secret Redaction Guard for [Pi Coding Agent](https://github.com/earendil-works/pi).**  
> *"What enters the event horizon remains destroyed forever."*

[![Pi Package](https://img.shields.io/badge/Pi--Package-Extension-76B900?logo=github&logoColor=white)](https://github.com/r1cc4rd0m4zz4/pi-dlp-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-555555.svg)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(zero%20npm)-brightgreen.svg)
[![Gitleaks Ready](https://img.shields.io/badge/Dual--Core-Gitleaks%20Ready-76B900.svg)](#dual-core-engine)

```bash
# ⚡ 1-Line Quick Install inside Pi:
pi install git:github.com/r1cc4rd0m4zz4/pi-dlp-guard
```

---

## Perché pi-dlp-guard?

Gli agenti di coding autonomi operano con ampi permessi di shell e manipolazione del filesystem. Senza guardrail rigorosi a livello di runtime:
* ⚠️ **Lettura ed Esfiltrazione di File Sensibili**: L'agente legge accidentalmente `.env`, `.env.local`, o percorsi utente come `~/.ssh/id_rsa` e `~/.aws/credentials`.
* ⚠️ **Evasione tramite Traversal & Symlinks**: Trick come `../../.env` o symlink creati per bypassare i controlli su nomi di file grezzi.
* ⚠️ **Leakage nel Prompt Wire (Ingress/Egress)**: Chiavi o token catturati in output di comandi (`cat`, `printenv`, `docker logs`) vengono inviati in chiaro via HTTPS ai provider LLM (Anthropic, OpenAI, Google).
* ⚠️ **Confused Deputy in Re-hydration**: Sistemi DLP a "vault reversibile" permettono a prompt injection di forzare chiamate di rete esterne re-idratando i token originali.

`pi-dlp-guard` applica la **legge di Hawking (Black Hole)** e il **modello di minaccia zero-trust (Mitnick)** a costo zero di dipendenze:

* ✅ **Hawking Black Hole (Irreversibile)**: L'informazione sensibile viene distrutta a senso unico. Nessun vault in memoria che re-idrata token per l'agente. Zero esfiltrazione laterale.
* ✅ **Dual Horizon Defense**:
  * *Horizon 1 (Transcript/Locale)*: Sanitizzazione immediata su `tool_result` prima che il testo tocchi il disco (`sessions/*.jsonl`) o il terminale.
  * *Horizon 2 (Wire/Provider)*: Filtraggio crittografico su `context` prima che qualsiasi frame lasci la macchina verso le API degli LLM.
* ✅ **Preservazione Relazionale Semantica ($A == A$)**: Se lo stesso segreto compare più volte, riceve lo stesso token effimero di sessione (es. `[REDACTED_AWS_KEY_#1]`). Il modello comprende le relazioni strutturali senza conoscere i valori in chiaro.
* ✅ **Integrità del Guardiano & Anti-Tampering (Controllore != Controllato)**: Protegge `~/.pi/agent/**`, la configurazione di sicurezza e il codice stesso di `pi-dlp-guard` contro modifiche, sovrascritture o cancellazioni (`rm`, `sed -i`, `write`, `edit`) tentate dall'agente o da prompt injection, garantendo che la sandbox non possa essere disarmata.
* ✅ **Dual-Layer Path Guard**: Regex lessicale immediata + risoluzione canonica reale (`fs.realpathSync`) per neutralizzare traversal (`../../`), link simbolici e link fisici.
* ✅ **Bash Lexer & Redirection Guard**: Ispezione degli argomenti e delle redirezioni shell (`<`, `>`, `>>`, `| tee`) bloccando l'accesso prima dello spawn.
* ✅ **Dual-Core Engine**: Motore regex nativo in-process ultrarapido (<0.05ms) + integrazione pipe opzionale con `gitleaks` per diff pre-commit e buffer grandi (>4KB).

---

## Architettura di Protezione

```text
       ┌─────────────────────────────────────────────────────────┐
       │                   USER PROMPT / SHELL                   │
       └────────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │                LAYER 1: TOOL CALL GUARD                 │
       │  • Block read/write/edit on .env, ~/.ssh, ~/.aws, .git  │
       │  • Anti-Tampering: protect ~/.pi/agent & guard code     │
       │  • Block bash redirection (<, >, >>) and sensitive args │
       │  • Canonical realpath check (anti-symlink/traversal)    │
       └────────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │           LAYER 2: HORIZON 1 (TOOL RESULT)              │
       │  • Redact secrets from stdout/stderr (<0.05ms regex)    │
       │  • Optional pipe scan with Gitleaks for large payloads  │
       │  • Relational token mapping ([REDACTED_AWS_KEY_#1])     │
       └────────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │           LAYER 3: HORIZON 2 (WIRE CONTEXT)             │
       │  • Final barrier: scans context before HTTP dispatch    │
       │  • Zero secrets leave the host machine                  │
       └─────────────────────────────────────────────────────────┘
```

---

## Comandi Interattivi Slash (`/dlp`)

All'interno di Pi è disponibile il comando di controllo operatore:

| Comando | Descrizione |
|---|---|
| `/dlp` o `/dlp status` | Mostra lo stato corrente (ATTIVA/DISATTIVATA), integrazione Gitleaks, conteggio segreti mascherati e percorsi protetti |
| `/dlp off` o `/dlp disable` | Disattiva temporaneamente la protezione per la sessione corrente (es. se devi modificare un `.env` autorizzato) |
| `/dlp on` o `/dlp enable` | Riattiva immediatamente la protezione DLP |
| `/dlp reload` | Ricarica a caldo le impostazioni da `~/.pi/agent/dlp-guard.json` senza riavviare Pi |

---

## Configurazione (`~/.pi/agent/dlp-guard.json`)

Il file viene auto-generato con i default raccomandati al primo avvio ed è completamente modificabile dall'utente:

```json
{
  "protectedPaths": [
    ".env*",
    ".git",
    "**/.git/**",
    "~/.ssh",
    "~/.ssh/**",
    "~/.aws",
    "~/.aws/**",
    "~/.gnupg",
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
    "~/.pi/agent/**",
    "**/pi-dlp-guard/**",
    "**/pi-ci-warden/**"
  ],
  "enableGitleaks": true,
  "gitleaksMinBytes": 4096,
  "gitleaksTimeoutMs": 500
}
```

---

## Verifica e Test (`npm test`)

La suite di regressione deterministica copre **21/21 asserzioni** sui rami negativi ed edge case:

```bash
npm test
```

```text
--- Group 1: Path Guard & Traversal Defense ---
  ✅ [PASS] Direct .env protection
  ✅ [PASS] Directory traversal on .env
  ✅ [PASS] Critical credentials & key paths
  ✅ [PASS] Symlink resolution to protected file (Mitnick Vector)
  ✅ [PASS] Normal benign files flow freely (Negative branch)
  ✅ [PASS] Guardian Integrity Protection (Anti-Tampering)

--- Group 2: Bash Shell Guard ---
  ✅ [PASS] Direct shell reading of .env
  ✅ [PASS] Shell input redirection (<)
  ✅ [PASS] Shell output redirection (> and >>)
  ✅ [PASS] Pipe to tee redirection (| tee)
  ✅ [PASS] Shell operations on SSH / AWS keys
  ✅ [PASS] Shell mutation blocking on Integrity paths
  ✅ [PASS] Benign shell commands pass through

--- Group 3: DLP Redaction & Relational Preservation ---
  ✅ [PASS] AWS Access Key Redaction
  ✅ [PASS] GitHub PAT Redaction
  ✅ [PASS] Private Key PEM Redaction
  ✅ [PASS] Hawking Relational Preservation (A == A)
  ✅ [PASS] Environment variable secret pattern
  ✅ [PASS] Negative branch: benign code is untouched

--- Group 4: Gitleaks Dual-Core & Fallback ---
  ✅ [PASS] Gitleaks pipe detection when binary exists
  ✅ [PASS] Graceful fallback when Gitleaks is disabled
```

---

## Installazione Locale

Per installarlo o collegarlo manualmente nel tuo ambiente Pi:

```bash
# Link locale permanente:
pi install /Users/mazric/gitapp/pi-dlp-guard
```

---

## License

MIT © 2026

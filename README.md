# 🛡️ Local AI System Log & Syslog Summarizer

Analyze noisy system logs (SSH auth logs, syslog, application stack traces)
and get plain-English root cause summaries — **entirely on your own machine**.
No log data, sanitized or not, ever leaves `localhost`.

```
Streamlit UI  →  Python DLP Scrubber  →  Ollama (Llama 3.2)
  (app.py)         (regex middleware)      (local inference, port 11434)
```

---

## How it works

1. **You paste or upload a log** in the Streamlit UI.
2. **Before anything is sent to the model**, `sanitize_log()` runs a set of
   regex patterns over the text and replaces sensitive values with
   placeholders like `[REDACTED_IP]`, `[REDACTED_EMAIL]`, etc.
3. The sanitized text is sent to a **local** Ollama server running the
   `llama3.2` model, with a system prompt that sets the model up as a
   Senior DevOps Engineer and tells it what kind of analysis to do.
4. The model's response is **streamed** back token-by-token so you're not
   staring at a blank screen while it thinks.

Nothing in this pipeline calls out to the internet. Ollama runs the model
in memory on your machine, and the Streamlit app talks to it over
`localhost:11434`.

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) installed and running locally
- The `llama3.2` model pulled:
  ```bash
  ollama pull llama3.2
  ```

---

## Setup

```bash
# 1. (Optional) create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Make sure Ollama is running
ollama serve                  # skip if it's already running as a service

# 4. Launch the app
streamlit run app.py
```

Streamlit will open the UI in your browser, typically at
`http://localhost:8501`.

---

## Using the app

1. **Paste a log** into the text area, and/or **upload a `.txt`/`.log` file**
   (two sample files are included in `sample_logs/` — see below).
2. Pick an **Analysis type** from the dropdown:
   | Mode | What it does |
   |---|---|
   | **Quick Summary** | 3–6 bullet plain-English summary of what happened |
   | **Root Cause & Fix** | Root cause, supporting evidence, fix steps, prevention tip |
   | **Security Audit** | Risk level, suspicious patterns, recommended action |
3. Click **🚀 Analyze Log**.
4. Expand **"Sanitization report"** to see what was redacted (and how many
   times) before anything was sent to the model.
5. Expand **"View sanitized log"** if you want to see the exact text the
   model received.
6. Read the streamed analysis on the right.

### Sidebar settings

- **Ollama host** — defaults to `http://localhost:11434`; change this if
  Ollama is running on a different port or a remote trusted host.
- **Model name** — defaults to `llama3.2`; change it to any other model
  you've pulled (e.g. `llama3.1`, `mistral`) without touching the code.

---

## What gets redacted

`app.py` scrubs the following before any text reaches the model:

| Category | Example | Replaced with |
|---|---|---|
| IPv4 addresses | `203.0.113.45` | `[REDACTED_IP]` |
| IPv6 addresses | `fe80::1ff:fe23:4567:890a` | `[REDACTED_IPV6]` |
| Email addresses | `jane.doe@example.com` | `[REDACTED_EMAIL]` |
| UUIDs | `550e8400-e29b-41d4-a716-446655440000` | `[REDACTED_UUID]` |
| MAC addresses | `00:1A:2B:3C:4D:5E` | `[REDACTED_MAC]` |
| AWS access keys | `AKIA...` | `[REDACTED_AWS_KEY]` |
| `key=`/`token=`/`password=` style assignments | `api_key=sk_live_abc123` | `key=[REDACTED_SECRET]` |
| Bearer tokens | `Bearer abc123def456` | `Bearer [REDACTED_TOKEN]` |

The system prompt also explicitly tells the model these placeholders are
intentional redactions, so it won't try to guess the original values or
comment on the redaction itself.

**Note:** this is a best-effort regex layer, not a guarantee. Review the
"Sanitization report" and "View sanitized log" panels before trusting logs
that contain anything highly sensitive.

---

## Project structure

```
ai_log_summarizer/
├── app.py                   # Streamlit UI + DLP middleware + Ollama streaming
├── requirements.txt         # streamlit, ollama
└── sample_logs/
    ├── auth_error.log       # SSH brute-force attempt + mixed sensitive data
    └── app_crash.log        # Java OOM stack trace + DB timeout warnings
```

Try loading either sample file via the file uploader to see the pipeline
end-to-end without needing your own logs handy.

---

## Troubleshooting

- **"⚠️ Error contacting Ollama"** in the result panel — Ollama isn't
  running, or the model name doesn't match a pulled model. Run
  `ollama serve` and `ollama pull llama3.2`, then retry.
- **Streaming doesn't render incrementally** — you're on a Streamlit
  version older than 1.31 (no `st.write_stream`); the app falls back to a
  manually-updated placeholder automatically, but upgrading Streamlit is
  recommended: `pip install -U streamlit`.
- **Nothing happens on file upload** — only `.txt` and `.log` extensions
  are accepted; rename the file or paste its contents directly instead.

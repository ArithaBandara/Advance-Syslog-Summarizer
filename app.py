"""
Local AI System Log & Syslog Summarizer
=========================================
A fully local pipeline: Streamlit (UI) -> Python DLP scrubber (middleware)
-> Ollama / Llama 3.2 (inference). No log data ever leaves the machine.

Run with:  streamlit run app.py
Requires:  Ollama running locally (default http://localhost:11434)
           with the "llama3.2" model already pulled (`ollama pull llama3.2`).
"""

import re
import time
from datetime import datetime

import ollama
import streamlit as st

# =============================================================================
# SECTION 1: CONFIGURATION
# =============================================================================

APP_TITLE = "🛡️ Local AI Log Summarizer"
DEFAULT_MODEL = "llama3.2"
DEFAULT_OLLAMA_HOST = "http://localhost:11434"

ANALYSIS_MODES = {
    "Quick Summary": (
        "Provide a short, plain-English summary (3-6 bullet points) of what is "
        "happening in this log. Focus on WHAT occurred, not deep analysis. "
        "Avoid speculation beyond what the log evidence supports."
    ),
    "Root Cause & Fix": (
        "Diagnose the ROOT CAUSE of the issue(s) in this log. Structure your "
        "answer as:\n"
        "1. **Root Cause** - the most likely underlying cause\n"
        "2. **Evidence** - the specific log lines/patterns that support this\n"
        "3. **Recommended Fix** - concrete, actionable steps to resolve it\n"
        "4. **Prevention** - one suggestion to prevent recurrence"
    ),
    "Security Audit": (
        "Review this log strictly from a SECURITY perspective. Identify any "
        "signs of brute-force attempts, unauthorized access, privilege "
        "escalation, unusual timing patterns, or other suspicious activity. "
        "Structure your answer as:\n"
        "1. **Risk Level** - Low / Medium / High / Critical\n"
        "2. **Findings** - suspicious patterns observed\n"
        "3. **Recommended Action** - what to investigate or lock down next\n"
        "If nothing suspicious is found, say so plainly - do not invent risks."
    ),
}

# =============================================================================
# SECTION 2: DATA LOSS PREVENTION (DLP) - REGEX SANITIZATION
# =============================================================================
# Every pattern below is compiled once at import time for performance.
# Order matters: more specific patterns (emails, UUIDs, keys) run before the
# generic IPv4 pattern where overlap could occur.

DLP_PATTERNS = [
    # (label, compiled_regex, replacement_token)
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
    (
        "UUID",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "[REDACTED_UUID]",
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "[REDACTED_AWS_KEY]",
    ),
    (
        "GENERIC_SECRET_ASSIGNMENT",
        # Matches patterns like: api_key=xxxxx, token: "xxxxx", password=xxxxx
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|auth)\b"
            r"\s*[=:]\s*['\"]?[A-Za-z0-9\-_\.]{6,}['\"]?"
        ),
        lambda m: re.split(r"[=:]", m.group(0), maxsplit=1)[0] + "=[REDACTED_SECRET]",
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-_\.]{10,}\b"),
        "Bearer [REDACTED_TOKEN]",
    ),
    (
        "MAC_ADDRESS",
        re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
        "[REDACTED_MAC]",
    ),
    (
        "IPV6",
        re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"),
        "[REDACTED_IPV6]",
    ),
    (
        "IPV4",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
        ),
        "[REDACTED_IP]",
    ),
]


def sanitize_log(raw_text: str) -> tuple[str, dict[str, int]]:
    """
    Scrub sensitive data out of raw log text before it ever reaches the LLM.

    Returns:
        (sanitized_text, counts) where `counts` maps each DLP category to
        the number of redactions made - shown to the user as a transparency
        report so they can verify nothing sensitive slipped through.
    """
    sanitized = raw_text
    counts: dict[str, int] = {}

    for label, pattern, replacement in DLP_PATTERNS:
        matches = pattern.findall(sanitized)
        if matches:
            counts[label] = len(matches)
            sanitized = pattern.sub(replacement, sanitized)

    return sanitized, counts


# =============================================================================
# SECTION 3: LLM INTEGRATION (OLLAMA)
# =============================================================================

def build_system_prompt(analysis_mode: str) -> str:
    """Construct the system prompt that sets the model's persona and task."""
    task_instructions = ANALYSIS_MODES[analysis_mode]
    return (
        "You are a Senior DevOps / Site Reliability Engineer with deep "
        "expertise in Linux systems, networking, and application logs. "
        "You analyze raw log excerpts and explain them in plain English "
        "for engineers who may not have time to read every line themselves.\n\n"
        "IMPORTANT CONTEXT: Some values in this log have been automatically "
        "redacted for privacy (e.g. [REDACTED_IP], [REDACTED_EMAIL], "
        "[REDACTED_UUID], [REDACTED_SECRET]). Treat these placeholders as "
        "opaque identifiers - do NOT attempt to guess or reconstruct the "
        "original values, and do NOT comment on the redaction itself.\n\n"
        "Be concise, technical, and actionable. Avoid filler and avoid "
        "restating the raw log back to the user verbatim.\n\n"
        f"TASK FOR THIS REQUEST:\n{task_instructions}"
    )


def stream_llm_response(client: "ollama.Client", model: str, system_prompt: str, log_text: str):
    """
    Generator that yields incremental text chunks from Ollama's streaming
    chat API. Designed to be passed directly to st.write_stream().
    """
    try:
        stream = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Here is the log to analyze:\n\n{log_text}"},
            ],
            stream=True,
        )
        for chunk in stream:
            piece = chunk.get("message", {}).get("content", "")
            if piece:
                yield piece
    except Exception as exc:  # noqa: BLE001 - surface any Ollama/connection error to the UI
        yield (
            "\n\n**⚠️ Error contacting Ollama.** "
            f"Details: `{exc}`\n\n"
            "Make sure the Ollama server is running (`ollama serve`) and that "
            f"the model `{model}` has been pulled (`ollama pull {model}`)."
        )


# =============================================================================
# SECTION 4: STREAMLIT UI
# =============================================================================

def render_sidebar() -> tuple[str, str]:
    """Render sidebar controls and return (ollama_host, model_name)."""
    st.sidebar.header("⚙️ Settings")
    ollama_host = st.sidebar.text_input(
        "Ollama host",
        value=DEFAULT_OLLAMA_HOST,
        help="Address of your local Ollama server.",
    )
    model_name = st.sidebar.text_input(
        "Model name",
        value=DEFAULT_MODEL,
        help="Must match a model you've already pulled via `ollama pull <model>`.",
    )
    st.sidebar.markdown("---")
    st.sidebar.markdown(
        "**🔒 Privacy note**\n\n"
        "All logs are scrubbed of IPs, emails, UUIDs, MAC addresses, and "
        "obvious secrets/tokens *before* they are sent to the model. "
        "Everything runs on `localhost` - nothing leaves this machine."
    )
    return ollama_host, model_name


def render_sanitization_report(counts: dict[str, int]) -> None:
    """Show a small transparency report of what was redacted, if anything."""
    if not counts:
        st.caption("✅ No sensitive patterns detected in the input.")
        return

    total = sum(counts.values())
    with st.expander(f"🕵️ Sanitization report — {total} item(s) redacted", expanded=False):
        for label, count in sorted(counts.items()):
            st.write(f"- **{label}**: {count} redacted")


def get_combined_log_input(pasted_text: str, uploaded_file) -> str:
    """Merge pasted text and an uploaded file into a single log blob."""
    parts = []
    if uploaded_file is not None:
        try:
            file_bytes = uploaded_file.getvalue()
            file_text = file_bytes.decode("utf-8", errors="ignore")
            parts.append(f"--- Uploaded file: {uploaded_file.name} ---\n{file_text}")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Could not read uploaded file: {exc}")

    if pasted_text and pasted_text.strip():
        parts.append(pasted_text.strip())

    return "\n\n".join(parts)


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")
    st.title(APP_TITLE)
    st.caption(
        "Paste or upload noisy logs. Everything is sanitized locally and "
        "summarized by a local LLM — zero data leaves your machine."
    )

    ollama_host, model_name = render_sidebar()

    # --- Input area -----------------------------------------------------
    col_left, col_right = st.columns([1, 1])

    with col_left:
        pasted_text = st.text_area(
            "Paste raw log content",
            height=280,
            placeholder="Paste auth.log, syslog, or an application stack trace here...",
        )
        uploaded_file = st.file_uploader("...or upload a log file", type=["txt", "log"])
        analysis_mode = st.selectbox("Analysis type", list(ANALYSIS_MODES.keys()))
        run_button = st.button("🚀 Analyze Log", type="primary", use_container_width=True)

    log_input = get_combined_log_input(pasted_text, uploaded_file)

    # --- Output area ------------------------------------------------------
    with col_right:
        st.subheader("Result")

        if run_button:
            if not log_input.strip():
                st.warning("Please paste some log text or upload a file first.")
                return

            # Step 1: DLP sanitization happens BEFORE anything touches the model.
            with st.spinner("Sanitizing log data (removing IPs, emails, UUIDs, secrets)..."):
                sanitized_text, redaction_counts = sanitize_log(log_input)
            render_sanitization_report(redaction_counts)

            # Optional: let the user inspect exactly what will be sent.
            with st.expander("View sanitized log (exactly what is sent to the model)"):
                st.code(sanitized_text, language="text")

            # Step 2: Build the prompt and stream the model's response.
            system_prompt = build_system_prompt(analysis_mode)
            client = ollama.Client(host=ollama_host)

            st.markdown(f"**Analysis — {analysis_mode}**")
            start_time = time.time()
            try:
                st.write_stream(
                    stream_llm_response(client, model_name, system_prompt, sanitized_text)
                )
            except AttributeError:
                # Fallback for older Streamlit versions without st.write_stream (<1.31)
                placeholder = st.empty()
                accumulated = ""
                for chunk in stream_llm_response(client, model_name, system_prompt, sanitized_text):
                    accumulated += chunk
                    placeholder.markdown(accumulated)

            elapsed = time.time() - start_time
            st.caption(f"Completed in {elapsed:.1f}s • {datetime.now().strftime('%H:%M:%S')}")
        else:
            st.info("Configure your input on the left, then click **Analyze Log**.")


if __name__ == "__main__":
    main()

"""
local ai system log & syslog summarizer
=========================================
a local tool that uses streamlit, python, and ollama to analyze system logs.
sensitive information is removed before logs are sent to the local ai model,
so no log data leaves the machine.

run with: streamlit run app.py
requires: ollama running locally (default http://localhost:11434)
          and the llama3.2 model (`ollama pull llama3.2`).
"""

import re
import time
from datetime import datetime

import ollama
import streamlit as st

# =============================================================================
# section 1: configuration
# =============================================================================

APP_TITLE = "🛡️ Local AI Log Summarizer"
DEFAULT_MODEL = "llama3.2"
DEFAULT_OLLAMA_HOST = "http://localhost:11434"

ANALYSIS_MODES = {
    "Quick Summary": (
        "Give a short summary (3-6 bullet points) of what is happening in "
        "this log. Focus on the main events and avoid guessing beyond what "
        "the log actually shows."
    ),
    "Root Cause & Fix": (
        "Look at the log and identify the most likely cause of the problem. "
        "Organize your answer into:\n"
        "1. **Root Cause** - what is most likely causing the issue\n"
        "2. **Evidence** - log entries that support your conclusion\n"
        "3. **Recommended Fix** - steps to fix the problem\n"
        "4. **Prevention** - one way to avoid the same issue in the future"
    ),
    "Security Audit": (
        "Check the log for possible security issues, such as failed login "
        "attempts, unauthorized access, privilege escalation, or unusual "
        "activity. Organize your answer into:\n"
        "1. **Risk Level** - Low / Medium / High / Critical\n"
        "2. **Findings** - anything suspicious found in the log\n"
        "3. **Recommended Action** - what should be checked or done next\n"
        "If everything looks normal, say so. Do not make up security risks."
    ),
}

# =============================================================================
# section 2: removing sensitive information
# =============================================================================

# compile the patterns once so we can reuse them whenever a log is checked.
# check the more specific patterns before the general ip address patterns.

DLP_PATTERNS = [
    # each entry contains a label, regex pattern, and replacement value.
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
        # look for common ways of storing passwords, tokens, and api keys.
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
    remove sensitive information from the log before sending it to the ai.

    returns the cleaned log along with a count of the items removed
    from each category. these counts are shown in the app.
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
# section 3: ollama integration
# =============================================================================

def build_system_prompt(analysis_mode: str) -> str:
    """create the instructions for the ai based on the selected analysis type."""
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
    send the log to ollama and display the response as it is generated.
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
    except Exception as exc:  # noqa: BLE001
        # show the connection error and remind the user to check ollama.
        yield (
            "\n\n**⚠️ Error contacting Ollama.** "
            f"Details: `{exc}`\n\n"
            "Make sure the Ollama server is running (`ollama serve`) and that "
            f"the model `{model}` has been pulled (`ollama pull {model}`)."
        )


# =============================================================================
# section 4: streamlit interface
# =============================================================================

def render_sidebar() -> tuple[str, str]:
    """show the sidebar settings and return the selected values."""
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
    """show how many sensitive items were removed from the log."""
    if not counts:
        st.caption("✅ No sensitive patterns detected in the input.")
        return

    total = sum(counts.values())
    with st.expander(f"🕵️ Sanitization report — {total} item(s) redacted", expanded=False):
        for label, count in sorted(counts.items()):
            st.write(f"- **{label}**: {count} redacted")


def get_combined_log_input(pasted_text: str, uploaded_file) -> str:
    """combine pasted log text and uploaded files into one string."""
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

    # input section
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

    # results section
    with col_right:
        st.subheader("Result")

        if run_button:
            if not log_input.strip():
                st.warning("Please paste some log text or upload a file first.")
                return

            # clean the log before passing it to the ai.
            with st.spinner("Sanitizing log data (removing IPs, emails, UUIDs, secrets)..."):
                sanitized_text, redaction_counts = sanitize_log(log_input)
            render_sanitization_report(redaction_counts)

            # let the user check the cleaned version before analysis.
            with st.expander("View sanitized log (exactly what is sent to the model)"):
                st.code(sanitized_text, language="text")

            # send the cleaned log to ollama and display the response.
            system_prompt = build_system_prompt(analysis_mode)
            client = ollama.Client(host=ollama_host)

            st.markdown(f"**Analysis — {analysis_mode}**")
            start_time = time.time()
            try:
                st.write_stream(
                    stream_llm_response(client, model_name, system_prompt, sanitized_text)
                )
            except AttributeError:
                # older streamlit versions do not support st.write_stream().
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

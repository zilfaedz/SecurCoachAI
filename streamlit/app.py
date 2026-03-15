import html
import json
import os
import time
from datetime import datetime
from pathlib import Path
import tomllib
from uuid import uuid4

import streamlit as st

try:
    import requests as http_requests
    USE_REQUESTS = True
except ImportError:
    from urllib import error, request as urllib_request
    USE_REQUESTS = False

try:
    import jwt as pyjwt
    USE_PYJWT = True
except ImportError:
    USE_PYJWT = False

DOMAINS = [
    "General Security",
    "Network Security",
    "Web App Security",
    "Cloud Security",
    "Cryptography",
    "Incident Response",
]
MODELS = ["llama-3.1-8b-instant", "llama-3.3-70b-versatile", "openai/gpt-oss-20b"]

st.set_page_config(
    page_title="SecurCoach AI",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ─── Secrets ────────────────────────────────────────────────────────────────

def load_root_secrets():
    path = Path(__file__).parent.parent / ".streamlit" / "secrets.toml"
    if not path.exists():
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def get_secret_value(key, default=""):
    try:
        return st.secrets[key]
    except Exception:
        return load_root_secrets().get(key, os.getenv(key, default)) or default


def get_react_app_url():
    return get_secret_value("REACT_APP_URL", "http://localhost:3000")

def get_groq_api_key():
    return get_secret_value("GROQ_API_KEY", "")

def get_supabase_url():
    return get_secret_value("SUPABASE_URL", "")

def get_supabase_key():
    return get_secret_value("SUPABASE_KEY", "")

def get_supabase_jwt_secret():
    return get_secret_value("SUPABASE_JWT_SECRET", "")

def get_supabase_chat_history_table():
    return get_secret_value("SUPABASE_CHAT_HISTORY_TABLE", "chat_history")


# ─── Auth ────────────────────────────────────────────────────────────────────

def verify_jwt_token(token: str):
    """
    Verify a Supabase JWT and return the user's email.
    Falls back to decoding without verification if SUPABASE_JWT_SECRET is not set
    (acceptable for school/dev use, not production).
    """
    if not token:
        return None
    jwt_secret = get_supabase_jwt_secret()
    if USE_PYJWT and jwt_secret:
        try:
            payload = pyjwt.decode(token, jwt_secret, algorithms=["HS256"], audience="authenticated")
            return payload.get("email", "")
        except Exception:
            return None
    # Fallback: decode without verification (dev only)
    try:
        import base64
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return payload.get("email", "")
    except Exception:
        return None


def ensure_auth_session_state():
    st.session_state.setdefault("is_authenticated", False)
    st.session_state.setdefault("auth_user_email", "")
    st.session_state.setdefault("conversation_loaded", False)
    st.session_state.setdefault("current_conversation_id", "")
    st.session_state.setdefault("conversation_summaries", [])


def apply_query_auth():
    """
    Authenticate via a JWT token passed as ?token= in the URL.
    This is secure because the token is cryptographically signed by Supabase.
    Falls back to ?auth_email= for local dev only.
    """
    token = st.query_params.get("token", "").strip()
    if token:
        email = verify_jwt_token(token)
        if email:
            st.session_state.is_authenticated = True
            st.session_state.auth_user_email = email.lower()
            st.session_state.conversation_loaded = False
            return

    # Local dev fallback only — remove before deploying to production
    auth_email = st.query_params.get("auth_email", "").strip().lower()
    if auth_email:
        st.session_state.is_authenticated = True
        st.session_state.auth_user_email = auth_email
        st.session_state.conversation_loaded = False


def get_user_id():
    return st.session_state.get("auth_user_email", "").strip().lower()


# ─── Supabase (using requests if available) ──────────────────────────────────

def supabase_request(method, path, payload=None, query="", extra_headers=None):
    supabase_url = get_supabase_url().rstrip("/")
    supabase_key = get_supabase_key()
    if not supabase_url or not supabase_key:
        return None
    url = f"{supabase_url}/rest/v1/{path}"
    if query:
        url = f"{url}?{query}"
    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    try:
        if USE_REQUESTS:
            resp = http_requests.request(
                method,
                url,
                headers=headers,
                json=payload,
                timeout=20,
            )
            resp.raise_for_status()
            return resp.json() if resp.text else None
        else:
            import json as _json
            from urllib import request as _req
            data = _json.dumps(payload).encode("utf-8") if payload is not None else None
            req = _req.Request(url, data=data, headers=headers, method=method)
            with _req.urlopen(req, timeout=20) as response:
                body = response.read().decode("utf-8")
                return _json.loads(body) if body else None
    except Exception as exc:
        st.session_state.supabase_error = str(exc)
        return None


# ─── Conversation helpers ─────────────────────────────────────────────────────

def load_conversation_summaries(user_id):
    from urllib.parse import quote
    query = (
        "select=conversation_id,message,created_at"
        f"&user_id=eq.{quote(user_id, safe='')}"
        "&order=created_at.desc"
    )
    rows = supabase_request("GET", get_supabase_chat_history_table(), query=query)
    if not isinstance(rows, list):
        return []
    seen = set()
    counts = {}
    for row in rows:
        cid = str(row.get("conversation_id", "")).strip()
        if cid:
            counts[cid] = counts.get(cid, 0) + 1
    summaries = []
    for row in rows:
        cid = str(row.get("conversation_id", "")).strip()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        message = str(row.get("message", "")).strip()
        summaries.append({
            "conversation_id": cid,
            "title": message[:32] + ("..." if len(message) > 32 else "") or "New Conversation",
            "created_at": str(row.get("created_at", "")).strip(),
            "message_count": counts.get(cid, 0),
        })
    return summaries


def load_messages_for_conversation(user_id, conversation_id):
    from urllib.parse import quote
    query = (
        "select=sender,message,created_at"
        f"&user_id=eq.{quote(user_id, safe='')}"
        f"&conversation_id=eq.{quote(conversation_id, safe='')}"
        "&order=created_at.asc"
    )
    rows = supabase_request("GET", get_supabase_chat_history_table(), query=query)
    if not isinstance(rows, list):
        return []
    messages = []
    for row in rows:
        created_at = str(row.get("created_at", "")).strip()
        messages.append({
            "role": "user" if str(row.get("sender", "")).strip().lower() == "user" else "assistant",
            "content": str(row.get("message", "")),
            "timestamp": created_at[11:16] if "T" in created_at else created_at[-5:],
        })
    return messages


def save_message(role, content):
    user_id = get_user_id()
    conversation_id = st.session_state.get("current_conversation_id", "")
    if not user_id or not conversation_id:
        return
    payload = {
        "user_id": user_id,
        "conversation_id": conversation_id,
        "sender": "user" if role == "user" else "ai",
        "message": content,
        "created_at": datetime.now().isoformat(),
    }
    supabase_request(
        "POST",
        get_supabase_chat_history_table(),
        payload=payload,
        extra_headers={"Prefer": "return=minimal"},
    )


def delete_conversation(conversation_id):
    from urllib.parse import quote
    user_id = get_user_id()
    if not user_id:
        return
    query = f"user_id=eq.{quote(user_id, safe='')}&conversation_id=eq.{quote(conversation_id, safe='')}"
    supabase_request(
        "DELETE",
        get_supabase_chat_history_table(),
        query=query,
        extra_headers={"Prefer": "return=minimal"},
    )


def append_message(role, content, timestamp=None):
    st.session_state.messages.append({
        "role": role,
        "content": content,
        "timestamp": timestamp or datetime.now().strftime("%H:%M"),
    })
    save_message(role, content)


def create_new_conversation():
    st.session_state.current_conversation_id = str(uuid4())
    st.session_state.messages = []
    st.session_state.conversation_loaded = True


def select_conversation(conversation_id):
    st.session_state.current_conversation_id = conversation_id
    st.session_state.messages = load_messages_for_conversation(get_user_id(), conversation_id)
    st.session_state.conversation_loaded = True


def refresh_conversations():
    user_id = get_user_id()
    if user_id:
        st.session_state.conversation_summaries = load_conversation_summaries(user_id)


# ─── Session state ────────────────────────────────────────────────────────────

def initialize_session_state():
    ensure_auth_session_state()
    apply_query_auth()
    st.session_state.setdefault("messages", [])
    st.session_state.setdefault("total_tokens", 0)
    st.session_state.setdefault("total_interactions", 0)
    st.session_state.setdefault("session_start", datetime.now())
    st.session_state.setdefault("supabase_error", None)
    st.session_state.setdefault("pending_prompt", None)
    st.session_state.setdefault("is_generating", False)
    st.session_state.setdefault("sidebar_open", True)
    st.session_state.setdefault("selected_model", MODELS[0])
    st.session_state.setdefault("selected_domain", DOMAINS[0])
    user_id = get_user_id()
    if st.session_state.is_authenticated and user_id:
        refresh_conversations()
        if not st.session_state.current_conversation_id:
            if st.session_state.conversation_summaries:
                select_conversation(st.session_state.conversation_summaries[0]["conversation_id"])
            else:
                create_new_conversation()
        elif not st.session_state.conversation_loaded:
            st.session_state.messages = load_messages_for_conversation(
                user_id, st.session_state.current_conversation_id
            )
        st.session_state.conversation_loaded = True


# ─── CSS ─────────────────────────────────────────────────────────────────────

def load_dashboard_css():
    # Try dashboard.css first, fall back to styles.css
    for css_name in ("dashboard.css", "styles.css"):
        css_path = Path(__file__).with_name(css_name)
        if css_path.exists():
            css = css_path.read_text(encoding="utf-8")
            st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
            return
    # If neither file exists, apply minimal inline fallback
    st.markdown(
        "<style>.stApp{background:#0b1220;}</style>",
        unsafe_allow_html=True,
    )


def render_chat_input_layout_css():
    if st.session_state.sidebar_open:
        left = "calc(25% + 1.6rem)"
        width = "calc(75% - 2.2rem)"
    else:
        left = "1.2rem"
        width = "calc(100% - 2.4rem)"
    st.markdown(
        f"""
        <style>
        [data-testid="stChatInput"] {{
            left: {left} !important;
            width: {width} !important;
            right: auto !important;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


# ─── UI Components ────────────────────────────────────────────────────────────

def render_login_redirect_notice():
    react_url = get_react_app_url().rstrip("/")
    st.markdown(
        f"""
        <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px;background:#222831;">
            <div style="width:min(520px,92vw);padding:36px;border-radius:20px;background:rgba(34,40,49,.92);border:1px solid rgba(148,137,121,.28);box-shadow:0 28px 64px rgba(0,0,0,.35);text-align:center;">
                <div style="font-family:'Montserrat',sans-serif;font-size:28px;font-weight:700;color:#dfd0b8;margin-bottom:10px;">SecurCoach AI</div>
                <div style="font-family:'Poppins',sans-serif;font-size:18px;font-weight:600;color:#948979;margin-bottom:12px;">Login starts in React</div>
                <p style="font-size:14px;line-height:1.7;color:rgba(223,208,184,.72);margin:0 0 22px;">Sign in through the React app first. After successful login, you will be redirected here automatically.</p>
                <a href="{react_url}" style="display:inline-block;padding:14px 22px;border-radius:12px;text-decoration:none;background:#948979;color:#222831;font-weight:600;">Open React Login</a>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def generate_response(model, system_prompt, api_messages):
    api_key = get_groq_api_key()
    if not api_key:
        return "Groq is not configured. Add `GROQ_API_KEY` to Streamlit secrets or your environment.", 0

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(
        {
            "role": "assistant" if m["role"] == "assistant" else "user",
            "content": m["content"],
        }
        for m in api_messages
    )
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.7,
        "max_completion_tokens": 1024,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    url = "https://api.groq.com/openai/v1/chat/completions"

    for attempt in range(2):
        try:
            if USE_REQUESTS:
                resp = http_requests.post(url, json=payload, headers=headers, timeout=60)
                if resp.status_code >= 500 and attempt == 0:
                    time.sleep(1.2)
                    continue
                if resp.status_code != 200:
                    return f"Groq request failed ({resp.status_code}). {resp.text}", 0
                data = resp.json()
            else:
                from urllib import error as _error, request as _req
                req = _req.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                try:
                    with _req.urlopen(req, timeout=60) as response:
                        data = json.loads(response.read().decode("utf-8"))
                except _error.HTTPError as exc:
                    details = exc.read().decode("utf-8", errors="replace")
                    if exc.code >= 500 and attempt == 0:
                        time.sleep(1.2)
                        continue
                    return f"Groq request failed ({exc.code}). {details}", 0

            choice = (data.get("choices") or [{}])[0]
            text = (
                choice.get("message", {}).get("content", "") or "Groq returned an empty answer."
            ).strip()
            usage = data.get("usage", {})
            total_tokens = usage.get("total_tokens", 0)
            return text, total_tokens

        except Exception as exc:
            return f"Groq request failed. {exc}", 0

    return "Groq is temporarily unavailable. Please try again in a few moments.", 0


def render_sidebar_panel():
    if not st.session_state.sidebar_open:
        if st.button(">", key="toggle_sidebar_closed", help="Open sidebar", use_container_width=True):
            st.session_state.sidebar_open = True
            st.rerun()
        return
    header_cols = st.columns([1, 5])
    with header_cols[0]:
        if st.button("<", key="toggle_sidebar_open", help="Collapse sidebar", use_container_width=True):
            st.session_state.sidebar_open = False
            st.rerun()
    with header_cols[1]:
        st.markdown(
            "<div class='brand-row'><div class='brand-icon'>SC</div><div><div class='brand-name'>SecurCoach AI</div><div class='brand-sub'>Security Training</div></div></div>",
            unsafe_allow_html=True,
        )
    if st.button("+ New Conversation", key="new_conv", use_container_width=True):
        create_new_conversation()
        refresh_conversations()
        st.rerun()
    st.markdown("<div class='history-label'>Chat History</div>", unsafe_allow_html=True)
    if st.session_state.conversation_summaries:
        for summary in st.session_state.conversation_summaries:
            cid = summary["conversation_id"]
            created_at = summary["created_at"].replace("T", " ")[:16] if summary["created_at"] else ""
            cols = st.columns([6, 1])
            with cols[0]:
                if st.button(
                    summary["title"],
                    key=f"conv_{cid}",
                    use_container_width=True,
                    help=f"{created_at} · {summary['message_count']} messages",
                ):
                    select_conversation(cid)
                    st.rerun()
                meta = f"{created_at} · {summary['message_count']} messages".strip(" ·")
                if meta:
                    st.markdown(f"<div class='conv-meta'>{html.escape(meta)}</div>", unsafe_allow_html=True)
            with cols[1]:
                if st.button("X", key=f"del_{cid}", help="Delete"):
                    delete_conversation(cid)
                    if cid == st.session_state.current_conversation_id:
                        st.session_state.current_conversation_id = ""
                        st.session_state.messages = []
                    refresh_conversations()
                    if not st.session_state.current_conversation_id:
                        if st.session_state.conversation_summaries:
                            select_conversation(
                                st.session_state.conversation_summaries[0]["conversation_id"]
                            )
                        else:
                            create_new_conversation()
                    st.rerun()
    else:
        st.markdown("<div class='chat-rail-empty'>No past conversations yet.</div>", unsafe_allow_html=True)


def render_messages():
    if not st.session_state.messages:
        st.markdown(
            f"<div class='empty-wrap'><div class='empty-icon'>SC</div><div class='empty-title'>Start a conversation</div>"
            f"<div class='empty-hint'>Ask anything about <strong style='color:#dfd0b8;'>{html.escape(st.session_state.selected_domain)}</strong>"
            f"<br>or choose a topic to get started.</div></div>",
            unsafe_allow_html=True,
        )
        return
    for msg in st.session_state.messages:
        render_message(msg)


def render_message(msg):
    is_user = msg["role"] == "user"
    row_cls = "user-row" if is_user else "ai-row"
    av_cls = "user-av" if is_user else "ai-av"
    av_lbl = "ME" if is_user else "AI"
    bub_cls = "user-bubble" if is_user else "ai-bubble"
    safe = html.escape(msg["content"]).replace("\n", "<br>")
    st.markdown(
        f"<div class='msg-row {row_cls}'><div class='avatar {av_cls}'>{av_lbl}</div>"
        f"<div class='bubble {bub_cls}'>{safe}"
        f"<div class='bubble-ts'>{html.escape(msg.get('timestamp', ''))}</div></div></div>",
        unsafe_allow_html=True,
    )


def render_loading_message():
    st.markdown(
        "<div class='msg-row ai-row'><div class='avatar ai-av'>AI</div>"
        "<div class='bubble ai-bubble'>Thinking<span style=\"opacity:0.3;font-family:'JetBrains Mono',monospace;\"> |</span></div></div>",
        unsafe_allow_html=True,
    )


def build_system_prompt():
    return (
        f"You are SecurCoach AI, an expert cybersecurity assistant specializing in {st.session_state.selected_domain}. "
        "Your role is to explain cybersecurity topics clearly and helpfully. "
        "Follow these guidelines:\n"
        "1. Use the NIST Cybersecurity Framework as a reference when applicable.\n"
        "2. Provide clear explanations with real-world examples and analogies.\n"
        "3. When relevant, include short code snippets for defensive techniques.\n"
        "4. Never provide instructions that could be used offensively or to harm systems.\n"
        "5. If a question is outside cybersecurity, politely redirect to security topics.\n"
        "6. Keep responses concise but thorough.\n"
        "7. Do not quiz the user, ask practice questions, or give tests unless the user explicitly asks for a quiz, reviewer, or practice mode.\n"
        "8. Answer the user's exact question directly before offering any optional extra help."
    )


def handle_prompt(prompt):
    if not st.session_state.current_conversation_id:
        create_new_conversation()
    append_message("user", prompt, datetime.now().strftime("%H:%M"))
    refresh_conversations()
    st.session_state.pending_prompt = {
        "model": st.session_state.selected_model,
        "system_prompt": build_system_prompt(),
        "api_messages": [{"role": m["role"], "content": m["content"]} for m in st.session_state.messages],
    }
    st.session_state.is_generating = True
    st.rerun()
    return {
        "model": st.session_state.selected_model,
        "system_prompt": (
            f"You are SecurCoach AI, an expert cybersecurity training coach specializing in {st.session_state.selected_domain}. "
            "Your role is to educate students and professionals on cybersecurity concepts. "
            "Follow these guidelines:\n"
            "1. Use the NIST Cybersecurity Framework as a reference when applicable.\n"
            "2. Provide clear explanations with real-world examples and analogies.\n"
            "3. When relevant, include short code snippets for defensive techniques.\n"
            "4. Never provide instructions that could be used offensively or to harm systems.\n"
            "5. If a question is outside cybersecurity, politely redirect to security topics.\n"
            "6. Keep responses concise but thorough — use bullet points for lists of steps or tips."
        ),
        "api_messages": [{"role": m["role"], "content": m["content"]} for m in st.session_state.messages],
    }


def render_dashboard():
    load_dashboard_css()
    render_chat_input_layout_css()
    if st.session_state.sidebar_open:
        col_sidebar, col_chat = st.columns([1, 3], gap="small")
    else:
        col_sidebar, col_chat = st.columns([0.001, 1], gap="small")
    with col_sidebar:
        render_sidebar_panel()
    with col_chat:
        if st.session_state.get("supabase_error"):
            st.caption("⚠️ Supabase sync failed on the last request.")
        render_messages()
        prompt = st.chat_input("Ask a security question...", key="chat_input")
        if prompt and not st.session_state.get("is_generating", False):
            handle_prompt(prompt)

        pending = st.session_state.get("pending_prompt")
        if pending and st.session_state.get("is_generating", False):
            assistant_slot = st.empty()
            with assistant_slot.container():
                render_loading_message()
            with st.spinner("SecurCoach AI is generating a response..."):
                reply, usage_tokens = generate_response(
                    pending["model"],
                    pending["system_prompt"],
                    pending["api_messages"],
                )
            append_message("assistant", reply, datetime.now().strftime("%H:%M"))
            assistant_slot.empty()
            render_message(st.session_state.messages[-1])
            st.session_state.total_tokens += usage_tokens
            st.session_state.total_interactions += 1
            st.session_state.pending_prompt = None
            st.session_state.is_generating = False
            refresh_conversations()


# ─── Entry point ──────────────────────────────────────────────────────────────

initialize_session_state()

if not st.session_state.is_authenticated:
    render_login_redirect_notice()
else:
    render_dashboard()

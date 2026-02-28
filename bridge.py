#!/usr/bin/env python3
"""Claude Code <-> Telegram Bridge"""

import os
import sys
import json
import re
import shutil
import signal
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

# Force unbuffered stdout with timestamps for launchd log files
import builtins as _builtins
from datetime import datetime as _dt
_orig_print = _builtins.print
def print(*args, **kwargs):
    kwargs.setdefault('flush', True)
    ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
    _orig_print(f"[{ts}]", *args, **kwargs)
import builtins
builtins.print = print

TMUX_SESSION = os.environ.get("TMUX_SESSION", "claude")
TMUX_BIN = os.environ.get("TMUX_BIN", shutil.which("tmux") or "tmux")
CHAT_ID_FILE = os.path.expanduser("~/.claude/telegram_chat_id")
PENDING_FILE = os.path.expanduser("~/.claude/telegram_pending")
HISTORY_FILE = os.path.expanduser("~/.claude/history.jsonl")
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
PORT = int(os.environ.get("PORT", "8080"))
BOT_USERNAME = ""  # set on startup via getMe
BOT_ID = 0

# --- Alert Auto-Fix Config ---
# Keywords that identify an alert message (for group chat detection)
ALERT_KEYWORDS = ["⚠️", "告警", "已超", "阈值", "Swap:", "磁盘:", "内存:", "CPU:"]
# Working dir for claude --print (project with SSH creds)
ALERT_CLAUDE_CWD = os.path.expanduser("~/seo/fuwuqi")
# Lock to prevent concurrent alert handling
_alert_lock = threading.Lock()

# --- OpenClaw Direct API Config ---
OPENCLAW_API = os.environ.get("OPENCLAW_API", "http://104.247.199.247:18080")
OPENCLAW_KEY = os.environ.get("OPENCLAW_KEY", "570d0e06f3df4011eafb32dc4b1f34d66ad5812311a7297c")
OPENCLAW_POLL_INTERVAL = int(os.environ.get("OPENCLAW_POLL_INTERVAL", "60"))
OPENCLAW_LAST_ID_FILE = os.path.expanduser("~/.claude/openclaw_last_alert_id")
ALERT_GROUP_CHAT_ID = int(os.environ.get("ALERT_GROUP_CHAT_ID", "-5269461624"))

# Serialize message processing
_message_lock = threading.Lock()

BOT_COMMANDS = [
    {"command": "clear", "description": "Clear conversation"},
    {"command": "resume", "description": "Resume session (shows picker)"},
    {"command": "continue_", "description": "Continue most recent session"},
    {"command": "loop", "description": "Ralph Loop: /loop <prompt>"},
    {"command": "stop", "description": "Interrupt Claude (Escape)"},
    {"command": "status", "description": "Check tmux status"},
]

BLOCKED_COMMANDS = [
    "/mcp", "/help", "/settings", "/config", "/model", "/compact", "/cost",
    "/doctor", "/init", "/login", "/logout", "/memory", "/permissions",
    "/pr", "/review", "/terminal", "/vim", "/approved-tools", "/listen"
]


def telegram_api(method, data):
    if not BOT_TOKEN:
        return None
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"Telegram API error: {e}")
        return None


def setup_bot_commands():
    result = telegram_api("setMyCommands", {"commands": BOT_COMMANDS})
    if result and result.get("ok"):
        print("Bot commands registered")


def send_typing_loop(chat_id, stop_event):
    while not stop_event.is_set():
        if not os.path.exists(PENDING_FILE):
            break
        telegram_api("sendChatAction", {"chat_id": chat_id, "action": "typing"})
        stop_event.wait(4)


def tmux_exists():
    return subprocess.run(
        [TMUX_BIN, "has-session", "-t", TMUX_SESSION],
        capture_output=True
    ).returncode == 0


def tmux_send_text(text):
    """Send text to tmux safely using load-buffer/paste-buffer for multiline support."""
    load = subprocess.run(
        [TMUX_BIN, "load-buffer", "-"],
        input=text.encode(), capture_output=True
    )
    if load.returncode != 0:
        raise RuntimeError(f"tmux load-buffer failed: {load.stderr.decode()}")
    paste = subprocess.run(
        [TMUX_BIN, "paste-buffer", "-t", TMUX_SESSION],
        capture_output=True
    )
    if paste.returncode != 0:
        raise RuntimeError(f"tmux paste-buffer failed: {paste.stderr.decode()}")


def tmux_send_key(key):
    """Send a special key (Enter, Escape) to tmux."""
    result = subprocess.run(
        [TMUX_BIN, "send-keys", "-t", TMUX_SESSION, key],
        capture_output=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"tmux send-keys '{key}' failed: {result.stderr.decode()}")


def _remove_pending():
    try:
        os.remove(PENDING_FILE)
    except FileNotFoundError:
        pass


def get_recent_sessions(limit=5):
    if not os.path.exists(HISTORY_FILE):
        return []
    sessions = []
    try:
        with open(HISTORY_FILE) as f:
            for line in f:
                try:
                    sessions.append(json.loads(line.strip()))
                except Exception:
                    continue
    except Exception:
        return []
    sessions.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return sessions[:limit]


def get_session_id(project_path):
    encoded = project_path.replace("/", "-").lstrip("-")
    for prefix in [f"-{encoded}", encoded]:
        project_dir = Path.home() / ".claude" / "projects" / prefix
        if project_dir.exists():
            jsonls = list(project_dir.glob("*.jsonl"))
            if jsonls:
                return max(jsonls, key=lambda p: p.stat().st_mtime).stem
    return None


def reply(chat_id, text):
    """Send a message to Telegram, splitting if over 4096 chars."""
    while text:
        chunk = text[:4096]
        text = text[4096:]
        telegram_api("sendMessage", {"chat_id": chat_id, "text": chunk})


def is_group_chat(chat_id):
    """Group/supergroup chat IDs are negative in Telegram."""
    return chat_id < 0


def should_respond(msg):
    """Determine if the bot should respond to this message.

    Private chats: always respond (any user).
    Group chats: only respond if @mentioned or replying to bot's message.
    """
    chat_id = msg.get("chat", {}).get("id")
    if not chat_id:
        return False

    # Private chat - always respond
    if not is_group_chat(chat_id):
        return True

    text = msg.get("text", "")

    # Check if message is a reply to the bot's message
    reply_to = msg.get("reply_to_message", {})
    if reply_to.get("from", {}).get("id") == BOT_ID:
        return True

    # Check if bot is @mentioned in text
    if BOT_USERNAME and f"@{BOT_USERNAME}" in text:
        return True

    # Check entities for bot mention (handles cases where username might differ in casing)
    for entity in msg.get("entities", []):
        if entity.get("type") == "mention":
            offset = entity.get("offset", 0)
            length = entity.get("length", 0)
            mention = text[offset:offset + length]
            if mention.lower() == f"@{BOT_USERNAME.lower()}":
                return True

    return False


def strip_bot_mention(text):
    """Remove @bot_username from the message text."""
    if not BOT_USERNAME:
        return text
    # Remove @username (case-insensitive) and clean up extra spaces
    cleaned = re.sub(rf'@{re.escape(BOT_USERNAME)}\b', '', text, flags=re.IGNORECASE)
    return ' '.join(cleaned.split()).strip()


def handle_callback(cb):
    chat_id = cb.get("message", {}).get("chat", {}).get("id")
    data = cb.get("data", "")
    telegram_api("answerCallbackQuery", {"callback_query_id": cb.get("id")})

    if not tmux_exists():
        reply(chat_id, "tmux session not found")
        return

    if data.startswith("resume:"):
        session_id = data.split(":", 1)[1]
        tmux_send_key("Escape")
        time.sleep(0.2)
        tmux_send_text("/exit")
        tmux_send_key("Enter")
        time.sleep(0.5)
        tmux_send_text(f"claude --resume {session_id} --dangerously-skip-permissions")
        tmux_send_key("Enter")
        reply(chat_id, f"Resuming: {session_id[:8]}...")

    elif data == "continue_recent":
        tmux_send_key("Escape")
        time.sleep(0.2)
        tmux_send_text("/exit")
        tmux_send_key("Enter")
        time.sleep(0.5)
        tmux_send_text("claude --continue --dangerously-skip-permissions")
        tmux_send_key("Enter")
        reply(chat_id, "Continuing most recent...")


def is_alert_message(text):
    """Return True if the message looks like a monitoring alert."""
    return any(kw in text for kw in ALERT_KEYWORDS)


def run_alert_autofix(chat_id, alert_text, silent=False):
    """Run claude --print to diagnose and fix a server alert. Runs in a thread."""
    if not _alert_lock.acquire(blocking=False):
        reply(chat_id, "⏳ 上一条告警正在处理中，请稍候...")
        return

    try:
        if not silent:
            reply(chat_id, f"🔍 收到告警，Claude 正在诊断并修复...\n\n{alert_text[:300]}")
        prompt = (
            "你收到了一条服务器运维监控告警，请立即分析并通过SSH执行修复操作。\n\n"
            f"告警内容：\n{alert_text}\n\n"
            "请：1) 判断是哪台服务器、什么问题；"
            "2) SSH连接该服务器诊断；"
            "3) 执行修复（如 swapoff/swapon、清理日志等）；"
            "4) 验证修复结果；"
            "5) 用中文简洁汇报：问题根因、操作步骤、修复后指标。"
        )
        claude_bin = shutil.which("claude") or os.path.expanduser("~/.local/bin/claude")
        result = subprocess.run(
            [claude_bin, "--print", "--dangerously-skip-permissions", prompt],
            capture_output=True, text=True, timeout=300, cwd=ALERT_CLAUDE_CWD
        )
        output = (result.stdout or "").strip() or result.stderr.strip() or "（无输出）"
        # Trim to Telegram message limit
        if len(output) > 3800:
            output = output[:3800] + "\n...(截断)"
        reply(chat_id, f"✅ 修复完成\n\n{output}")
    except subprocess.TimeoutExpired:
        reply(chat_id, "⏰ Claude 处理超时（5分钟），请手动检查")
    except Exception as e:
        reply(chat_id, f"❌ 自动修复失败：{e}")
    finally:
        _alert_lock.release()


# --- OpenClaw Direct API Integration ---

def _read_last_alert_id():
    try:
        with open(OPENCLAW_LAST_ID_FILE) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def _write_last_alert_id(alert_id):
    with open(OPENCLAW_LAST_ID_FILE, "w") as f:
        f.write(str(alert_id))


def poll_openclaw_alerts():
    """Fetch new alerts from OpenClaw API."""
    url = f"{OPENCLAW_API}/api/alerts?api_key={OPENCLAW_KEY}&limit=20"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        if not data.get("success"):
            return []
        alerts = data.get("alerts", [])
    except Exception as e:
        print(f"[openclaw] API error: {e}")
        return []

    last_id = _read_last_alert_id()
    new_alerts = [a for a in alerts if a.get("id", 0) > last_id]
    new_alerts.sort(key=lambda a: a.get("id", 0))
    return new_alerts


def _format_alert_details(details_str):
    """Format raw JSON details into readable text."""
    try:
        d = json.loads(details_str) if isinstance(details_str, str) else details_str
    except (json.JSONDecodeError, TypeError):
        return ""
    lines = []
    for k, v in d.items():
        if isinstance(v, float):
            v = f"{v:.2f}"
        if isinstance(v, list):
            continue  # skip complex nested data
        lines.append(f"  • {k}: {v}")
    return "\n".join(lines)


def handle_openclaw_alert(alert):
    """Process a single OpenClaw alert: notify group + trigger Claude auto-fix."""
    alert_id = alert.get("id", 0)
    server = alert.get("server_name", "?")
    level = alert.get("level", "?").upper()
    message = alert.get("message", "")
    server_ip = alert.get("server_ip", "")
    details = alert.get("details", "")
    created = alert.get("created_at", "")

    # Format details for display
    details_text = _format_alert_details(details)

    # Single clean message: alert + details + status
    notify = f"🔔 告警 #{alert_id} | {server} [{level}]\n\n"
    notify += f"• {message}\n"
    notify += f"• IP: {server_ip}\n"
    if created:
        notify += f"• 时间: {created}\n"
    if details_text:
        notify += f"\n{details_text}\n"
    notify += f"\n🔧 Claude 正在分析修复中..."

    reply(ALERT_GROUP_CHAT_ID, notify)
    print(f"[openclaw] New alert #{alert_id}: {server} [{level}] {message[:50]}")

    # Update last seen ID immediately
    _write_last_alert_id(alert_id)

    # Build prompt for Claude (include raw details for full context)
    prompt_text = (
        f"⚠️ {server} [{level}] {message}\n"
        f"IP: {server_ip}\n"
        f"详细数据: {details}"
    )

    # Trigger auto-fix (silent=True to avoid duplicate message)
    run_alert_autofix(ALERT_GROUP_CHAT_ID, prompt_text, silent=True)


def openclaw_alert_loop():
    """Background thread: poll OpenClaw API for new alerts."""
    # Initialize last_id to current max to avoid processing old alerts on first run
    if not os.path.exists(OPENCLAW_LAST_ID_FILE):
        try:
            existing = poll_openclaw_alerts.__wrapped__() if hasattr(poll_openclaw_alerts, '__wrapped__') else None
        except Exception:
            existing = None
        if existing is None:
            # Fetch current alerts to find max ID
            url = f"{OPENCLAW_API}/api/alerts?api_key={OPENCLAW_KEY}&limit=1"
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.loads(r.read())
                alerts = data.get("alerts", [])
                if alerts:
                    _write_last_alert_id(alerts[0].get("id", 0))
                    print(f"[openclaw] Initialized last_id={alerts[0].get('id', 0)}")
            except Exception as e:
                print(f"[openclaw] Init error: {e}")

    print(f"[openclaw] Monitoring started (interval={OPENCLAW_POLL_INTERVAL}s)")

    while not _shutdown.is_set():
        _shutdown.wait(OPENCLAW_POLL_INTERVAL)
        if _shutdown.is_set():
            break
        try:
            new_alerts = poll_openclaw_alerts()
            if new_alerts:
                print(f"[openclaw] Found {len(new_alerts)} new alert(s)")
                for alert in new_alerts:
                    handle_openclaw_alert(alert)
        except Exception as e:
            print(f"[openclaw] Loop error: {e}")


def handle_message(update):
    msg = update.get("message", {})
    text = msg.get("text", "")
    chat_id = msg.get("chat", {}).get("id")

    if not text or not text.strip() or not chat_id:
        return

    text = text.strip()

    # --- DEBUG: log all incoming messages ---
    from_username = msg.get("from", {}).get("username", "")
    from_id = msg.get("from", {}).get("id", "")
    print(f"[DBG] chat={chat_id} from=@{from_username}(id={from_id}) text={text[:60]!r}")

    # --- Alert Auto-Fix: trigger on any group message containing alert keywords ---
    if is_group_chat(chat_id) and is_alert_message(text):
        threading.Thread(target=run_alert_autofix, args=(chat_id, text), daemon=True).start()
        return

    # Group chat filtering: only respond to @mentions and replies to bot
    if is_group_chat(chat_id) and not should_respond(msg):
        return

    # Strip @bot_username from the text before processing
    if is_group_chat(chat_id):
        text = strip_bot_mention(text)
        if not text:
            return

    with open(CHAT_ID_FILE, "w") as f:
        f.write(str(chat_id))

    if text.startswith("/"):
        # In groups, Telegram appends @botname to commands, e.g. /status@Mac9988_bot
        cmd = text.split()[0].lower().split("@")[0]

        if cmd == "/status":
            status = "running" if tmux_exists() else "not found"
            reply(chat_id, f"tmux '{TMUX_SESSION}': {status}")
            return

        if cmd == "/stop":
            if tmux_exists():
                tmux_send_key("Escape")
            _remove_pending()
            reply(chat_id, "Interrupted")
            return

        if cmd == "/clear":
            if not tmux_exists():
                reply(chat_id, "tmux not found")
                return
            tmux_send_key("Escape")
            time.sleep(0.2)
            tmux_send_text("/clear")
            tmux_send_key("Enter")
            reply(chat_id, "Cleared")
            return

        if cmd == "/continue_":
            if not tmux_exists():
                reply(chat_id, "tmux not found")
                return
            tmux_send_key("Escape")
            time.sleep(0.2)
            tmux_send_text("/exit")
            tmux_send_key("Enter")
            time.sleep(0.5)
            tmux_send_text("claude --continue --dangerously-skip-permissions")
            tmux_send_key("Enter")
            reply(chat_id, "Continuing...")
            return

        if cmd == "/loop":
            if not tmux_exists():
                reply(chat_id, "tmux not found")
                return
            parts = text.split(maxsplit=1)
            if len(parts) < 2:
                reply(chat_id, "Usage: /loop <prompt>")
                return
            prompt = parts[1]
            full = f"{prompt} Output <promise>DONE</promise> when complete."
            with _message_lock:
                with open(PENDING_FILE, "w") as f:
                    f.write(str(int(time.time())))
                stop_event = threading.Event()
                threading.Thread(target=send_typing_loop, args=(chat_id, stop_event), daemon=True).start()
                tmux_send_text(f"/ralph-loop:ralph-loop '{full}' --max-iterations 5 --completion-promise 'DONE'")
                time.sleep(0.3)
                tmux_send_key("Enter")
            reply(chat_id, "Ralph Loop started (max 5 iterations)")
            return

        if cmd == "/resume":
            sessions = get_recent_sessions()
            if not sessions:
                reply(chat_id, "No sessions")
                return
            kb = [[{"text": "Continue most recent", "callback_data": "continue_recent"}]]
            for s in sessions:
                sid = get_session_id(s.get("project", ""))
                if sid:
                    kb.append([{"text": s.get("display", "?")[:40] + "...", "callback_data": f"resume:{sid}"}])
            telegram_api("sendMessage", {"chat_id": chat_id, "text": "Select session:", "reply_markup": {"inline_keyboard": kb}})
            return

        if cmd in BLOCKED_COMMANDS:
            reply(chat_id, f"'{cmd}' not supported (interactive)")
            return

    # Regular message - serialize to prevent concurrent PENDING_FILE conflicts
    with _message_lock:
        if os.path.exists(PENDING_FILE):
            reply(chat_id, "Processing previous message, please wait...")
            return

        print(f"[{chat_id}] {text[:50]}...")
        with open(PENDING_FILE, "w") as f:
            f.write(str(int(time.time())))

        if not tmux_exists():
            reply(chat_id, "tmux not found")
            _remove_pending()
            return

        stop_event = threading.Event()
        threading.Thread(target=send_typing_loop, args=(chat_id, stop_event), daemon=True).start()
        try:
            tmux_send_text(text)
            tmux_send_key("Enter")
        except Exception as e:
            _remove_pending()
            stop_event.set()
            reply(chat_id, f"Error: {e}")


def poll_updates(offset=0, timeout=15):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?timeout={timeout}&offset={offset}"
    result_box = [None]
    error_box = [None]

    def _do_poll():
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout + 10) as r:
                result_box[0] = json.loads(r.read())
        except Exception as e:
            error_box[0] = e

    t = threading.Thread(target=_do_poll, daemon=True)
    t.start()
    t.join(timeout=timeout + 15)
    if t.is_alive():
        print("Poll STUCK - forcing skip")
        return []
    if error_box[0]:
        print(f"Poll error: {error_box[0]}")
        return []
    if result_box[0] and result_box[0].get("ok"):
        return result_box[0].get("result", [])
    return []


_shutdown = threading.Event()


def main():
    if not BOT_TOKEN:
        print("Error: TELEGRAM_BOT_TOKEN not set")
        return

    # Graceful shutdown via flag (avoid raising in signal handler during blocking I/O)
    def shutdown_handler(signum, frame):
        _remove_pending()
        print(f"Received signal {signum}, shutting down")
        _shutdown.set()
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    # Get bot info (username, id) for @mention detection
    global BOT_USERNAME, BOT_ID
    try:
        req = urllib.request.Request(f"https://api.telegram.org/bot{BOT_TOKEN}/getMe")
        with urllib.request.urlopen(req, timeout=10) as r:
            me = json.loads(r.read())
            if me.get("ok"):
                BOT_USERNAME = me["result"].get("username", "")
                BOT_ID = me["result"].get("id", 0)
                print(f"Bot: @{BOT_USERNAME} (id={BOT_ID})")
    except Exception as e:
        print(f"Warning: getMe failed: {e}")

    # Clear any existing webhook
    try:
        urllib.request.urlopen(f"https://api.telegram.org/bot{BOT_TOKEN}/deleteWebhook")
        print("Webhook cleared, using polling mode")
    except Exception:
        pass

    setup_bot_commands()
    print(f"Bridge on :{PORT} | tmux: {TMUX_SESSION} | PID: {os.getpid()} (polling mode)")

    # Start OpenClaw alert monitoring
    if OPENCLAW_KEY:
        threading.Thread(target=openclaw_alert_loop, daemon=True).start()

    # Startup: use timeout=0 (non-blocking) to avoid 409 Conflict with previous instance's
    # active long-poll, but still PROCESS any pending updates so nothing is missed.
    offset = 0
    try:
        flush = poll_updates(offset=0, timeout=0)
        print(f"Startup: {len(flush)} pending update(s)")
        for update in flush:
            offset = update.get("update_id", 0) + 1
            if "message" in update:
                handle_message(update)
            elif "callback_query" in update:
                handle_callback(update["callback_query"])
    except Exception as e:
        print(f"Startup flush error (non-fatal): {e}")

    backoff = 1
    poll_count = 0

    while not _shutdown.is_set():
        try:
            updates = poll_updates(offset)
            poll_count += 1
            if poll_count % 20 == 1:
                print(f"[heartbeat] poll #{poll_count}, offset={offset}, updates={len(updates)}")
            if _shutdown.is_set():
                break
            for update in updates:
                offset = update.get("update_id", 0) + 1
                if "message" in update:
                    handle_message(update)
                elif "callback_query" in update:
                    handle_callback(update["callback_query"])
            backoff = 1
        except KeyboardInterrupt:
            print("Stopped")
            break
        except Exception as e:
            if _shutdown.is_set():
                break
            print(f"Error: {e}")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    main()
    # Exit non-zero on SIGTERM so launchd (SuccessfulExit:false) restarts us
    if _shutdown.is_set():
        sys.exit(1)

#!/bin/bash
umask 077
cd /Users/ph88vito/claudecode-telegram

source .secrets_env || { echo "Failed to source .secrets_env"; exit 1; }
if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
    echo "TELEGRAM_BOT_TOKEN not set"
    exit 0  # exit 0 so KeepAlive:SuccessfulExit:false won't restart
fi

export TELEGRAM_BOT_TOKEN
export PORT=8088
export TMUX_SESSION=claude
export CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1

# OpenClaw alert monitoring
export OPENCLAW_API="http://104.247.199.247:18080"
export OPENCLAW_KEY="570d0e06f3df4011eafb32dc4b1f34d66ad5812311a7297c"
export OPENCLAW_POLL_INTERVAL=60
export ALERT_GROUP_CHAT_ID="-5269461624"

# Kill any lingering bridge.py to prevent 409 Conflict
pkill -f "python3.*bridge\.py" 2>/dev/null
sleep 1

# Ensure tmux session exists - retry with backoff instead of crash-looping
TMUX_BIN=$(which tmux 2>/dev/null || echo "/opt/homebrew/bin/tmux")
MAX_RETRIES=5
RETRY=0
while ! "$TMUX_BIN" has-session -t "$TMUX_SESSION" 2>/dev/null; do
    RETRY=$((RETRY + 1))
    if [ "$RETRY" -gt "$MAX_RETRIES" ]; then
        echo "ERROR: Failed to create tmux session after $MAX_RETRIES retries"
        exit 1  # launchd will retry after ThrottleInterval (300s)
    fi
    echo "Creating tmux session '$TMUX_SESSION' (attempt $RETRY/$MAX_RETRIES)..."
    "$TMUX_BIN" new-session -d -s "$TMUX_SESSION" -c /Users/ph88vito \
        "claude --dangerously-skip-permissions"
    sleep $((RETRY * 3))
done
echo "tmux session '$TMUX_SESSION' ready"

exec /usr/bin/python3 -u bridge.py

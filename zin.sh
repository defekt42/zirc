#!/bin/sh
# zin.sh — Minimalist, High-Security tmux input helper (v1.8)
PANE="zirc:0.0"
PROMPT="zirc> "
ZCONF="${HOME}/.config/zirc"
NICKS_FILE="${ZCONF}/nicklist.txt"
HIST_FILE="${ZCONF}/.zirc_history"
NICK_UPDATE_INTERVAL=8

# --- Initialization ---
mkdir -p "$ZCONF" && chmod 700 "$ZCONF"
touch "$NICKS_FILE" && chmod 600 "$NICKS_FILE"
touch "$HIST_FILE" && chmod 600 "$HIST_FILE"

# --- Function: watch_nicks ---
watch_nicks() {
    local temp_file="${NICKS_FILE}.$$"
    
    # Extract nicks from chat: <nickname>
    tmux capture-pane -t "$PANE" -p -S -1000 2>/dev/null | \
        grep -o '<[^>]*>' | \
        sed 's/[<>]//g' | \
        grep -v '^$' | \
        grep -v '^[0-9]*$' | \
        grep -Ev '^(password|Password|prompt|boat|bort|brot|aibird)$' > "$temp_file"
    
    # Merge with existing nicks and sort
    if [ -f "$NICKS_FILE" ]; then
        cat "$NICKS_FILE" "$temp_file" 2>/dev/null | sort -u > "${temp_file}.merged"
        mv "${temp_file}.merged" "$temp_file"
    fi
    
    if [ -s "$temp_file" ]; then
        chmod 600 "$temp_file"
        mv "$temp_file" "$NICKS_FILE"
    else
        rm -f "$temp_file"
    fi
}

# --- Cleanup ---
cleanup() {
    [ -n "$WATCHER_PID" ] && kill "$WATCHER_PID" 2>/dev/null
    rm -f "${NICKS_FILE}".* 2>/dev/null
    exit 0
}
trap cleanup INT TERM EXIT

# --- Background Nick Watcher ---
while :; do
    sleep "$NICK_UPDATE_INTERVAL"
    watch_nicks
done &
WATCHER_PID=$!

# --- Main rlwrap Loop ---
rlwrap -H "$HIST_FILE" -D2 -S "$PROMPT" -b '' -f "$NICKS_FILE" sh -c '
PANE="'"$PANE"'"
while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in
        /quit|:quit)
            tmux send-keys -t "$PANE" "/quit" Enter 2>/dev/null
            exit 0 ;;
        *) tmux send-keys -t "$PANE" "$line" Enter 2>/dev/null ;;
    esac
done
'
exit 0

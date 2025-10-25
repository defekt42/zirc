#!/bin/sh
# zstart.sh — Fully integrated secure IRC launcher

# --- Minimal Secure Environment ---
# Set a minimal, secure PATH to prevent executing spoofed binaries
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

# --- Configuration ---
readonly SESSION="zirc"
readonly HOME_DIR="/home/defekt" # IMPORTANT: Adjust if your HOME is different
readonly ZIRC_BASE="${HOME_DIR}/.suckless/irc/zirc-sec"
readonly IRC_CLIENT="${ZIRC_BASE}/z18"
readonly INPUT_HELPER="${ZIRC_BASE}/zin.sh"
readonly ZCONF="${HOME_DIR}/.config/zirc"

# IRC Connection Settings
readonly SERVER="irc.libera.chat"
readonly PORT=6697
readonly NICK="defekt"
readonly PASSWORD_ARG="prompt" # Using 'prompt' for security
readonly CHANNEL="#unixtalk"

# Tmux Settings
readonly WINDOW_NAME="Double-Octothorpe"
readonly OUTPUT_PANE="irc-output"
readonly INPUT_PANE="rlwrap-input"
readonly HISTORY_LIMIT=10000
readonly INPUT_HEIGHT=1 # Height of the input pane (1 line)

# --- Helper Functions ---

# Secure error reporting
error_exit() {
printf "Error: %s\n" "$1" >&2
exit "${2:-1}"
}

# Verify command exists
check_command() {
command -v "$1" >/dev/null 2>&1 || \
error_exit "'$1' command not found. Please install it first."
}

# Verify file is executable AND securely permissioned (not world-writable)
check_executable() {
local file="$1"

# Check 1: Existence and Executability
[ -x "$file" ] || \
error_exit "$(basename "$file") not found or not executable at: $file"

# Check 2: Security (Must not be world-writable)
# Check if the 'other' category has the 'w' bit set.
# We check the fourth digit of the octal permissions.
local permissions_digit=$(stat -c "%a" "$file" 2>/dev/null | cut -c 4)
if [ -w "$file" ] && [ "$permissions_digit" -eq "2" ]; then
error_exit "$(basename "$file") is world-writable (permissions error). Please run: chmod o-w '$file'"
fi
# Optional warning if group-writable (e.g., 775 or 777)
local group_permissions_digit=$(stat -c "%a" "$file" 2>/dev/null | cut -c 3)
if [ -w "$file" ] && [ "$group_permissions_digit" -eq "2" ]; then
printf "Warning: $(basename "$file") is group-writable. Consider running: chmod g-w '%s'\n" "$file" >&2
fi
}

# Secure directory creation with proper permissions
ensure_secure_dir() {
if [ ! -d "$1" ]; then
mkdir -p "$1" || error_exit "Failed to create directory: $1"
chmod 700 "$1" || error_exit "Failed to set permissions on: $1"
fi
}

# --- Pre-Flight Checks ---
check_command tmux
check_executable "$IRC_CLIENT"
check_executable "$INPUT_HELPER"
ensure_secure_dir "$ZCONF"

# Verify we can write to config directory
[ -w "$ZCONF" ] || error_exit "Config directory not writable: $ZCONF"

# --- Session Management ---

# Check if session already exists
if tmux has-session -t "$SESSION" 2>/dev/null; then
printf "Attaching to existing ZIRC session...\n"
# Use exec to replace the shell process with tmux attach (more efficient)
exec tmux attach -t "$SESSION"
fi

# --- Session Creation ---
printf "Starting new ZIRC session...\n"

# 1. Create session with IRC client (detached)
tmux new-session -d -s "$SESSION" -n "$WINDOW_NAME" \
"stty -echo; $IRC_CLIENT $SERVER $PORT $NICK $PASSWORD_ARG $CHANNEL" || \
error_exit "Failed to create tmux session"

# 2. Apply general tmux settings
tmux set-option -t "$SESSION" history-limit "$HISTORY_LIMIT" 2>/dev/null
tmux set-option -t "$SESSION" set-clipboard off 2>/dev/null # Prevent clipboard leakage
tmux set-option -t "$SESSION" allow-rename off 2>/dev/null # Prevent session renaming

# 3. Rename output pane for clarity
tmux rename-pane -t "${SESSION}:${WINDOW_NAME}.0" "$OUTPUT_PANE" 2>/dev/null

# 4. Create input pane and rename it (1 line at bottom)
tmux split-window -t "${SESSION}:${WINDOW_NAME}" -v -l 1 "$INPUT_HELPER"
if [ $? -ne 0 ]; then
    error_exit "Failed to create input pane"
fi
tmux rename-pane -t "${SESSION}:${WINDOW_NAME}.1" "$INPUT_PANE" 2>/dev/null

# 5. Enable mouse support for scrolling ONLY (no pane switching/selection)
tmux set-option -t "$SESSION" mouse on 2>/dev/null

# 6. Disable ALL mouse pane interactions (important for locking focus)
tmux unbind-key -T root MouseDown1Pane 2>/dev/null
tmux unbind-key -T root MouseDown1Status 2>/dev/null
#tmux unbind-key -T root MouseDrag1Pane 2>/dev/null
#tmux unbind-key -T root MouseDrag1Border 2>/dev/null

# 7. Configure mouse wheel scrolling (auto copy-mode for output pane)
tmux bind-key -T root WheelUpPane \
if-shell -F -t = "#{mouse_any_flag}" \
"send-keys -M" \
"if-shell -F -t = '#{pane_in_mode}' \
'send-keys -M' \
'copy-mode -e; send-keys -M'" 2>/dev/null

# 8. Disable ALL pane-switching keybindings (essential for locking focus)
tmux unbind-key -T prefix o 2>/dev/null
tmux unbind-key -T prefix Up 2>/dev/null
tmux unbind-key -T prefix Down 2>/dev/null
tmux unbind-key -T prefix Left 2>/dev/null
tmux unbind-key -T prefix Right 2>/dev/null
tmux unbind-key -T prefix \; 2>/dev/null

# 9. Remove pane borders entirely (cleaner look, no visual distraction)
tmux set-option -t "$SESSION" pane-border-status off 2>/dev/null
tmux set-option -t "$SESSION" pane-border-style "fg=black" 2>/dev/null
tmux set-option -t "$SESSION" pane-active-border-style "fg=black" 2>/dev/null

# 10. Lock focus on input pane permanently (cursor will always be here)
tmux select-pane -t "${SESSION}:${WINDOW_NAME}.1" 2>/dev/null

# --- Attach to Session ---
printf "Attaching to ZIRC session...\n"
exec tmux attach -t "$SESSION"

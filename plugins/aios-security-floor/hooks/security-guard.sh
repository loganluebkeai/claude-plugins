#!/bin/bash
# PreToolUse security hook - CLIENT CUT (v1, ported from operator v3 2026-08-12)
# TrueNorth Intell / AIOS. Exit 0 = allow, exit 2 = hard block.
#
# DESIGN RULE (unchanged from v3)
#   Block only what is CATASTROPHIC and IRREVERSIBLE. Everything else passes
#   silently. A gate that fires during normal work gets worked around; a gate
#   that never fires is still there when it matters. In normal client work
#   this script should never once trigger.
#
# WHY THIS EXISTS ON A CLIENT BOX
#   Deny rules and this hook are evaluated in EVERY permission mode, including
#   bypassPermissions. This is the floor under the permission gas pedal: the
#   client drives the mode; this layer stays put. (Doctrine 2026-08-12.)
#
# WHY NOT jq
#   jq is NOT bundled with Git Bash. A jq-dependent version parses every field
#   empty on a machine without it, skips every check, and exits 0 = allow all.
#   The hook looks installed while the gate is decorative. This version uses
#   sed (always present) and falls back to raw-payload matching, so it cannot
#   silently no-op.
#
# CLIENT-CUT CHANGES FROM OPERATOR v3
#   * path-independent: the maintenance sentinel lives BESIDE THIS SCRIPT
#     (workspace-scoped install: <workspace>/.claude/hooks/), not in a
#     hardcoded home directory
#   * mac stat fallback (stat -f %m) so the maintenance window works on macOS
#   * NEW section 1b: secret paths referenced in a COMMAND with a read/copy
#     verb are blocked too. Operator v3 only checked the file_path field, so
#     `cat secrets/.env` through Bash walked past section 1.
#   * client-facing block messages (they render in the client's terminal)
#
# WHAT THIS DELIBERATELY DOES NOT BLOCK (the v3 friction lesson)
#   git reset --hard / checkout . / restore . / clean -f / branch -D
#     -> reflog-recoverable, and they fire during normal work
#   scoped deletes (rm -rf node_modules) -> routine
#
# KEEP THIS FILE PURE ASCII.

INPUT=$(cat)

block() {
  printf '{"decision": "block", "reason": "%s"}\n' "$1" >&2
  exit 2
}

# --- extraction: sed only, no external dependency -------------------------
val() { printf '%s' "$INPUT" | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }
TOOL=$(val tool_name)
FILE=$(val file_path)
CMD=$(val command)

# If extraction found nothing usable, match against the whole payload instead.
# Conservative: may over-block in contrived cases, never silently allows.
if [ -z "$TOOL" ] && [ -z "$FILE" ] && [ -z "$CMD" ]; then
  FILE="$INPUT"; CMD="$INPUT"
fi

FILE="${FILE//\\//}"          # normalize windows separators
CMD_N="${CMD//\\//}"

# =========================================================================
# 1. SECRET EXFILTRATION - never legitimate for the assistant
# =========================================================================
if [ -n "$FILE" ] && [[ "$FILE" != *".env.example"* ]]; then
  if [[ "$FILE" == *".env"* ]] || \
     [[ "$FILE" == *"/.ssh/"* ]] || \
     [[ "$FILE" == *"/secrets/"* ]] || \
     [[ "$FILE" == *".pem" ]] || \
     [[ "$FILE" == *".key" ]] || \
     [[ "$FILE" == *"/.aws/"* ]] || \
     [[ "$FILE" == *"/.gnupg/"* ]] || \
     [[ "$FILE" == *"/.git-credentials"* ]] || \
     [[ "$FILE" == *"/.netrc"* ]] || \
     [[ "$FILE" == *"/.npmrc"* ]] || \
     [[ "$FILE" == *"/.config/gcloud/"* ]]; then
    block "Security floor: reading credential or secret files is blocked. Your keys stay private, even from the assistant."
  fi
fi

# 1b. Same secret paths named inside a COMMAND with a read/copy verb.
#     (A command like: cat secrets/.env carries no file_path field.)
if [ -n "$CMD" ] && [[ "$CMD_N" != *".env.example"* ]]; then
  if [[ "$CMD_N" == *".env"* || "$CMD_N" == *"/secrets/"* || "$CMD_N" == *"secrets/"* || \
        "$CMD_N" == *"/.ssh/"* || "$CMD_N" == *".pem"* || "$CMD_N" == *".git-credentials"* ]]; then
    if [[ "$CMD_N" == *"cat "* || "$CMD_N" == *"type "* || "$CMD_N" == *"Get-Content"* || \
          "$CMD_N" == *"head "* || "$CMD_N" == *"tail "* || "$CMD_N" == *"more "* || \
          "$CMD_N" == *"less "* || "$CMD_N" == *"grep "* || "$CMD_N" == *"findstr"* || \
          "$CMD_N" == *"Select-String"* || "$CMD_N" == *"cp "* || "$CMD_N" == *"copy "* || \
          "$CMD_N" == *"Copy-Item"* || "$CMD_N" == *"scp "* ]]; then
      block "Security floor: reading or copying credential files through a command is blocked."
    fi
  fi
fi

# =========================================================================
# 2. REMOTE CODE EXECUTION - download piped straight into a shell
# =========================================================================
if [ -n "$CMD" ]; then
  if [[ "$CMD" == *"curl"* || "$CMD" == *"wget"* || "$CMD" == *"Invoke-WebRequest"* || "$CMD" == *"iwr "* ]] && \
     [[ "$CMD" == *"| bash"* || "$CMD" == *"|bash"* || "$CMD" == *"| sh"* || "$CMD" == *"|sh"* || \
        "$CMD" == *"| zsh"*  || "$CMD" == *"|zsh"*  || \
        "$CMD" == *"iex"*    || "$CMD" == *"Invoke-Expression"* ]]; then
    block "Security floor: piping downloaded content straight into a shell is blocked."
  fi
fi

# =========================================================================
# 3. DESTRUCTION OF WHAT GIT DOES NOT PROTECT
#    secrets/ is gitignored; the assistant memory dir lives outside the repo.
#    Code and outputs are in git and therefore recoverable - not blocked here.
# =========================================================================
if [ -n "$CMD" ]; then
  if [[ "$CMD_N" == *"rm "* || "$CMD_N" == *"del "* || "$CMD_N" == *"Remove-Item"* || \
        "$CMD_N" == *"mv "* || "$CMD_N" == *"Move-Item"* ]]; then
    if [[ "$CMD_N" == *"/secrets"* || "$CMD_N" == *"/memory"* || \
          "$CMD_N" == *".claude/projects"* || "$CMD_N" == *"/.env"* ]]; then
      block "Security floor: blocked a destructive operation on files git does not protect (secrets or assistant memory)."
    fi
  fi

  # SCOPED DELETES: recursive force-delete aimed at a root, a home, or a drive
  # root is catastrophic. Scoped deletes (node_modules, build dirs) still pass.
  if [[ "$CMD_N" == *"rm -rf /"* || "$CMD_N" == *"rm -fr /"* || \
        "$CMD_N" == *"rm -rf ~"*  || "$CMD_N" == *"rm -rf \$HOME"* || \
        "$CMD_N" == *"rm -rf C:/"* || "$CMD_N" == *"rm -rf ."* ]]; then
    block "Security floor: blocked a recursive delete aimed at a root or home directory."
  fi
fi

# =========================================================================
# 4. GATE TAMPERING - with a maintenance escape hatch
#
#    Blocks the assistant from rewriting its own gate on a single instruction
#    (the prompt-injection case). Does NOT lock anyone out: the operator (or
#    the client, deliberately) touches the sentinel, then edits within 15 min.
#
#      touch <workspace>/.claude/hooks/.maintenance
#      (plugin-carried guard: touch .maintenance beside the cached hook;
#       .claude/plugins is gated too since v1.2.0, 2026-08-21)
#
#    Two deliberate steps beats one injected instruction.
# =========================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
MAINT="$SCRIPT_DIR/.maintenance"
maint_open() {
  [ -f "$MAINT" ] || return 1
  local now mt age
  now=$(date +%s)
  mt=$(stat -c %Y "$MAINT" 2>/dev/null || stat -f %m "$MAINT" 2>/dev/null || echo 0)
  age=$(( now - mt ))
  [ "$age" -lt 900 ]          # 15 minute window
}

targets_gate() {
  [[ "$1" == *".claude/hooks"* || "$1" == *".claude/settings.json"* || "$1" == *".claude/plugins"* ]]
}

if targets_gate "$FILE" || targets_gate "$CMD_N"; then
  # reads stay allowed - only writes are gated
  WRITEISH=0
  [[ "$TOOL" == "Edit" || "$TOOL" == "Write" || "$TOOL" == "NotebookEdit" ]] && WRITEISH=1
  if [ -n "$CMD" ] && [[ "$CMD_N" == *">"* || "$CMD_N" == *"cp "* || "$CMD_N" == *"mv "* || \
       "$CMD_N" == *"tee "* || "$CMD_N" == *"rm "* || "$CMD_N" == *"sed -i"* || \
       "$CMD_N" == *"Set-Content"* || "$CMD_N" == *"Out-File"* ]]; then
    WRITEISH=1
  fi
  if [ "$WRITEISH" -eq 1 ] && ! maint_open; then
    block "Security floor: the gate protects itself. To edit it deliberately: touch a .maintenance file beside security-guard.sh (workspace .claude/hooks/ or the plugin cache hooks/ dir), then retry within 15 minutes."
  fi
fi

exit 0

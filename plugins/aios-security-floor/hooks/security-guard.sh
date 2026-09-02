#!/bin/bash
# PreToolUse security hook - CLIENT CUT (v1, ported from operator v3 2026-08-12;
# gate widened + sections 5 and 6 added 2026-09-01 - ships as plugin v1.3.0)
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
#   * 2026-09-01: section 5 (nested launch with the floor off = BLOCK),
#     section 6 (file leaving the machine / email send = ASK), /run/aios/
#     (the age tmpfs decrypt path on a hands box) joins the secret paths
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

# ask: the hook's third answer (added 2026-09-01). Exit 0 with a permissionDecision
# of "ask" on stdout - the CLI then puts the call in front of a human (a
# permission prompt in a session; the Approve/Deny keyboard in the Telegram
# lane; a deny wherever nobody is there to answer). Used ONLY for shapes that
# are legitimate often enough that a hard block would get worked around, but
# consequential enough that silence is wrong: sending a file off the machine.
# MEASURED 9/1 (not documented): an ask is a real prompt in default and
# acceptEdits, and in the Agent SDK lane with a permission callback. Under
# bypassPermissions it is NOT a prompt - an interactive bypass session ran
# the command, a headless one denied it. A bypass box has opted out of
# prompts, this one included; the hard blocks above still hold there.
ask() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}\n' "$1"
  exit 0
}

# --- extraction: bash only, no external dependency ------------------------
# val <key>: the first string value for <key>, honouring \" escapes inside it.
# (2026-09-01: the earlier sed form stopped at the first quote character, so
#  a command like  curl -F "file=@x" https://y  was seen as  curl -F \  and
#  every pattern after the quote was invisible - a silent-allow class in the
#  extractor itself. This walker returns the same value when no escaped quote
#  is present, and the whole value when one is.)
val() {
  local rest="${INPUT#*\"$1\"}"
  [ "$rest" = "$INPUT" ] && return 0            # key absent
  rest="${rest#*:}"
  [[ "$rest" == *\"* ]] || return 0             # not a string value
  rest="${rest#*\"}"
  local out="" chunk
  while :; do
    chunk="${rest%%\"*}"
    if [ "$chunk" = "$rest" ]; then out="$out$chunk"; break; fi   # no closing quote
    out="$out$chunk"
    rest="${rest#*\"}"
    if [[ "$chunk" == *"\\" ]]; then           # that quote was escaped: keep going
      out="${out%\\}\""
      continue
    fi
    break
  done
  printf '%s' "$out"
}
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
     [[ "$FILE" == *"/.config/gcloud/"* ]] || \
     [[ "$FILE" == *"/run/aios/"* ]]; then
    block "Security floor: reading credential or secret files is blocked. Your keys stay private, even from the assistant."
  fi
fi

# 1b. Same secret paths named inside a COMMAND with a read/copy verb.
#     (A command like: cat secrets/.env carries no file_path field.)
if [ -n "$CMD" ] && [[ "$CMD_N" != *".env.example"* ]]; then
  if [[ "$CMD_N" == *".env"* || "$CMD_N" == *"/secrets/"* || "$CMD_N" == *"secrets/"* || \
        "$CMD_N" == *"/.ssh/"* || "$CMD_N" == *".pem"* || "$CMD_N" == *".git-credentials"* || \
        "$CMD_N" == *"/run/aios/"* ]]; then
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
  # 2026-09-01 (P0 of the escape-route pass): four more files that grant
  # persistence sat outside this gate - settings.local.json (allow rules
  # remove the human prompt), .mcp.json and ~/.claude.json (an MCP server =
  # code execution at next start), and command/floor (the bot-lane copy of
  # this very file, loaded via --settings for every headless spawn).
  [[ "$1" == *".claude/hooks"* || "$1" == *".claude/settings.json"* || "$1" == *".claude/plugins"* || \
     "$1" == *".claude/settings.local.json"* || "$1" == *".mcp.json"* || "$1" == *".claude.json"* || \
     "$1" == *"command/floor"* ]]
}

if targets_gate "$FILE" || targets_gate "$CMD_N"; then
  # reads stay allowed - only writes are gated
  WRITEISH=0
  [[ "$TOOL" == "Edit" || "$TOOL" == "Write" || "$TOOL" == "NotebookEdit" ]] && WRITEISH=1
  # A stderr-to-null redirect writes nothing (2026-09-01: `ls <gated dir>
  # 2>/dev/null` was blocked as tampering). Drop the harmless forms before the
  # `>` test; a redirect into a real file keeps its `>` and stays gated.
  CMD_W="${CMD_N//2>&1/}"
  CMD_W="${CMD_W//2>\/dev\/null/}"
  CMD_W="${CMD_W//>\/dev\/null/}"
  if [ -n "$CMD" ] && [[ "$CMD_W" == *">"* || "$CMD_N" == *"cp "* || "$CMD_N" == *"mv "* || \
       "$CMD_N" == *"tee "* || "$CMD_N" == *"rm "* || "$CMD_N" == *"sed -i"* || \
       "$CMD_N" == *"Set-Content"* || "$CMD_N" == *"Out-File"* ]]; then
    WRITEISH=1
  fi
  if [ "$WRITEISH" -eq 1 ] && ! maint_open; then
    block "Security floor: the gate protects itself (hooks, settings, settings.local, .mcp.json, .claude.json, plugins, command/floor). To edit deliberately: touch a .maintenance file beside security-guard.sh, then retry within 15 minutes."
  fi
fi

# =========================================================================
# 5. NESTED LAUNCH WITH THE FLOOR SWITCHED OFF (added 2026-09-01)
#
#    A floored session can start a child session that never had a floor:
#    --safe-mode and --restricted switch the settings layer off (user hooks
#    and plugins never load), --setting-sources drops user settings,
#    --plugin-dir loads arbitrary code, --settings injects configuration, and
#    a redirected CLAUDE_CONFIG_DIR is a config dir with no floor in it.
#    Proven 8/29 (escape-route finding #10): the parent guard allowed the
#    command, the child printed a planted key. A plain nested `claude -p` stays
#    allowed - it fires in normal work and would get worked around. A nested
#    --dangerously-skip-permissions is NOT gated: bypass is a permission mode,
#    the child still loads its settings, and the floor holds under it.
# =========================================================================
if [ -n "$CMD" ]; then
  if [[ "$CMD_N" == "claude "* || "$CMD_N" == *" claude "* || "$CMD_N" == *"/claude "* || \
        "$CMD_N" == *"claude.exe"* || "$CMD_N" == *"claude.cmd"* || \
        "$CMD_N" == *"CLAUDE_CONFIG_DIR="* ]]; then
    if [[ "$CMD_N" == *"--safe-mode"* || "$CMD_N" == *"--restricted"* || \
          "$CMD_N" == *"--setting-sources"* || "$CMD_N" == *"--plugin-dir"* || \
          "$CMD_N" == *"--settings "* || "$CMD_N" == *"--settings="* || \
          "$CMD_N" == *"CLAUDE_CONFIG_DIR="* ]]; then
      block "Security floor: starting a nested Claude Code session with the floor switched off (--safe-mode, --restricted, --setting-sources, --settings, --plugin-dir, a redirected config dir) is blocked. A plain nested claude -p is fine."
    fi
  fi
fi

# =========================================================================
# 6. SENDING A FILE OFF THE MACHINE - ASK, do not block (added 2026-09-01)
#
#    Section 2 stops a download piped into a shell; nothing watched the other
#    direction. An upload is often legitimate (a deploy, a report to a client
#    portal), so it is an ask, not a block: the person sees the exact command
#    and taps once. Narrow by design - a plain GET, a JSON body typed inline,
#    and git push all pass silently. Section 1b still hard-blocks a copy verb
#    on a secret path, and runs first.
# =========================================================================
if [ -n "$CMD" ]; then
  OUTBOUND=0
  if [[ "$CMD_N" == *"curl"* || "$CMD_N" == *"wget"* || "$CMD_N" == *"Invoke-RestMethod"* || \
        "$CMD_N" == *"Invoke-WebRequest"* || "$CMD_N" == *"irm "* || "$CMD_N" == *"iwr "* ]]; then
    if [[ "$CMD_N" == *"-d @"* || "$CMD_N" == *"--data @"* || "$CMD_N" == *"--data-binary @"* || \
          "$CMD_N" == *"--data-raw @"* || "$CMD_N" == *"=@"* || "$CMD_N" == *"--upload-file"* || \
          "$CMD_N" == *" -T "* || "$CMD_N" == *"--post-file"* || "$CMD_N" == *"--body-file"* || \
          "$CMD_N" == *"-InFile"* ]]; then
      OUTBOUND=1
    fi
  fi
  if [[ "$CMD_N" == *"scp "* || "$CMD_N" == *"rsync "* || "$CMD_N" == *"sftp "* ]] && \
     [[ "$CMD_N" == *"@"* && "$CMD_N" == *":"* ]]; then
    OUTBOUND=1
  fi
  if [ "$OUTBOUND" -eq 1 ]; then
    ask "Security floor: this command sends a file to another machine. Approve only if you meant to send it."
  fi
  # A network verb that names a credential-shaped path asks even with no file body.
  if [[ "$CMD_N" == *"curl"* || "$CMD_N" == *"wget"* || "$CMD_N" == *"Invoke-RestMethod"* || \
        "$CMD_N" == *"Invoke-WebRequest"* || "$CMD_N" == *"scp "* || "$CMD_N" == *"rsync "* || \
        "$CMD_N" == *"ssh "* || "$CMD_N" == *"nc "* || "$CMD_N" == *"ncat "* ]]; then
    if [[ "$CMD_N" != *".env.example"* ]] && \
       [[ "$CMD_N" == *".env"* || "$CMD_N" == *"secrets/"* || "$CMD_N" == *".pem"* || \
          "$CMD_N" == *".key"* || "$CMD_N" == *"credentials"* || "$CMD_N" == *"/.ssh/"* || \
          "$CMD_N" == *"/run/aios/"* ]]; then
      ask "Security floor: a network command names a credential-shaped path. Approve only if you meant to send it."
    fi
  fi
fi

# 6b. Email leaving the machine through a connector. Workspace doctrine is
#     drafts only, never sends - so a send is always worth one tap.
if [[ "$TOOL" == "mcp__claude_ai_Gmail__send_message" || "$TOOL" == "mcp__claude_ai_Gmail__forward" ]]; then
  ask "Security floor: this sends an email in your name. Approve to send."
fi

exit 0

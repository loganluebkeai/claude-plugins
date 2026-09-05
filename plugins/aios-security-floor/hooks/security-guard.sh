#!/bin/bash
# PreToolUse security hook - CLIENT CUT (v1, ported from operator v3 2026-08-12;
# gate widened + sections 5 and 6 added 2026-09-01 - plugin v1.3.0;
# 2026-09-02 audit fixes - plugin v1.4.0: backslash-path bypass of the
# self-protection gate, an assistant-creatable maintenance sentinel, and
# code-execution tools that carry no command/file_path field)
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
#   * 2026-09-02 (workspace audit, three bypasses verified by behavior):
#     section 0 blocks code-execution tools by NAME (python_repl, executeCode,
#     run_command) - they carry `code`, not `command`, and walked past every
#     check; path normalization collapses the doubled slashes a JSON-escaped
#     backslash pair leaves (C:\\x -> C://x), which had silently un-gated every
#     self-protection target on Windows spellings; section 4a makes the
#     maintenance sentinel something only a person at their own terminal can
#     create (touch/New-Item/echo were not write verbs, so the assistant could
#     open its own window and edit the gate in one turn)
#   * 2026-09-04 (PowerShell-tool investigation, four gaps verified by behavior):
#     section 1b is now VERB-INDEPENDENT (it enumerated read verbs, so the
#     aliases gc/sls and the .NET file methods read a decoy secret straight
#     past it); the .env.example exception is token-scoped (naming it anywhere
#     used to disable the whole secret check - `cat .env.example secrets/.env`);
#     section 3 (delete) and section 6 (upload) got the same alias/.NET
#     widening; section 4a now fires only when the sentinel is a TARGET, not
#     when its name merely appears as content. The verb-independent 1b carries
#     non-surfacing exemptions (metadata, inline interpreters, ssh -i key use)
#     measured against 4200+ logged commands so the operator workflow is not
#     blocked - a pure path-only block would have hit 47 legitimate commands
#   * 2026-09-04 late (content-vs-target pass, plugin v1.6.0): a rule that
#     scans the raw command string cannot tell a protected path NAMED AS
#     CONTENT (a commit message, a heredoc body, a grep pattern) from one
#     being ACTED ON. Found live twice the same day: a heredoc commit body
#     that mentioned command/floor was blocked as a write to it (section 4),
#     and `claude --help | grep -- --safe-mode` was blocked as a nested
#     launch with the floor off (section 5). Both sections now reason over
#     a command SKELETON and its pipeline STAGES (helpers below section 3);
#     anything the helpers cannot classify falls back to the old whole-string
#     rule. Section 5 also gains `--bare` (skips hooks - the floor off by
#     another name) and `--plugin-url` (arbitrary hooks from a URL), both
#     present in CLI 2.1.261 and neither gated before. The same pass found
#     that the JSON newline escape had been normalizing to the two characters
#     /n, gluing every later line to the letter n (a line-start rm, a
#     newline-separated ls+cat of a secret, and a `claude --safe-mode` on
#     its own line all walked past their sections); newlines are decoded
#     first now and backslash-newline continuations are joined.
#     MEASURED: the 30-day audit log (4149 unique Bash/PowerShell commands)
#     replayed through 1.5.0 and this build - 33 decisions changed. 24 new
#     blocks: five real writes to protected files 1.5.0 missed (Remove-Item
#     on the plugin cache, WriteAllBytes on settings.local.json, python
#     heredocs editing ~/.claude.json and a settings.json), four nested
#     launches with the floor off, fifteen conservative reads of protected
#     files through an interpreter, loop or assignment (cat / git show /
#     Get-Content remain the read path). 8 blocks lifted, every one a
#     content mention (commit bodies, grep of the guard, git add lists,
#     --help piped to sed). 1 ask lifted: a newline-glued `cat` that had
#     read as the ncat network verb.
#
# WHAT THIS DELIBERATELY DOES NOT BLOCK (the v3 friction lesson)
#   git reset --hard / checkout . / restore . / clean -f / branch -D
#     -> reflog-recoverable, and they fire during normal work
#   scoped deletes (rm -rf node_modules) -> routine
#
# KEEP THIS FILE PURE ASCII.

# Bumped with plugin.json on every release. verify-floor.sh prints it beside
# the behavior probes; _test-floor-plugin.sh fails when the two disagree.
GUARD_VERSION="1.6.0"

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

# =========================================================================
# 0. CODE-EXECUTION TOOLS THAT NEVER REACH THE CHECKS BELOW (added 2026-09-02)
#
#    Every check below reads `command` or `file_path`. A tool that executes
#    code through a different field is invisible to all of them: an MCP python
#    REPL and the IDE Jupyter bridge both carry `code`, and `python_repl`
#    reading secrets/.env walked past the whole floor untouched (workspace
#    audit 2026-09-02, verified by behavior). Matched on the tool NAME before
#    any field is extracted, so a new field shape cannot reopen it. Bash stays
#    the one audited execution lane. Client boxes ship with zero MCP servers,
#    so on a client this never fires; it exists for the operator box and for
#    any client who later adds a server.
# =========================================================================
case "$TOOL" in
  *python_repl*|*executeCode*|*execute_code*|*run_code*|*exec_code*|*run_command*|*run_shell*|*shell_exec*|*execute_command*)
    block "Security floor: code-execution tools outside the audited Bash lane (python_repl, executeCode, run_command) are not available on this machine."
    ;;
esac

# Normalize Windows separators for MATCHING ONLY (never used as a path).
# The payload is JSON, so a Windows path arrives escaped: C:\\Users\\x. A plain
# backslash-to-slash replace turned that into C://Users//x, and every gate
# pattern with an interior slash (.claude/hooks, .claude/settings.json,
# command/floor) silently stopped matching on the normal Windows spelling.
# Found by behavior 2026-09-02: Write C:\...\security-guard.sh ALLOW while
# Write C:/.../security-guard.sh BLOCK. Fix: escaped pair -> one slash, then
# any single backslash -> slash, then collapse whatever doubles remain.
FILE="${FILE//\\\\//}"
FILE="${FILE//\\//}"
while [[ "$FILE" == *"//"* ]]; do FILE="${FILE//\/\//\/}"; done
# 2026-09-04 late (found by replaying the audit log): the JSON newline escape
# \n used to fall through this mapping as the two characters /n, so every
# command on a line after the first was glued to the letter n - a line-start
# `rm -rf secrets/` missed section 3's word boundary, `ls secrets/` + newline +
# `cat secrets/.env` passed section 1b's metadata exemption (a newline was not
# in its chain-separator list), and `claude --safe-mode` on its own line was
# never seen by section 5. JSON escapes are decoded to real characters FIRST
# (escaped backslash pair -> placeholder -> slash), so a newline is a newline.
# A backslash immediately before a newline is a line continuation (the shell
# joins the lines); it arrives as an escaped backslash pair + the newline
# escape and is joined here so a wrapped `git add -- \ ... \` stays one command.
CMD_N="${CMD//\\\\\\n/ }"
CMD_N="${CMD_N//\\\\/$'\001'}"
CMD_N="${CMD_N//\\n/$'\n'}"
CMD_N="${CMD_N//\\r/}"
CMD_N="${CMD_N//\\t/ }"
CMD_N="${CMD_N//$'\001'//}"
CMD_N="${CMD_N//\\//}"
while [[ "$CMD_N" == *"//"* ]]; do CMD_N="${CMD_N//\/\//\/}"; done

# --- verb-INDEPENDENT secret helpers (added 2026-09-04) -------------------
# WHY (found by behavior 2026-09-04): section 1b matched a FIXED LIST of read
# verbs (cat, Get-Content, ...), so PowerShell aliases (gc, sls), .NET file
# methods ([IO.File]::ReadAllText), and a pipe (ls secrets/ | xargs cat) each
# read a decoy secrets/.env straight past the gate. Enumerating verbs is
# whack-a-mole (aliases, .NET, future shells are unbounded). These helpers gate
# on the INVARIANT - a credential path is named - and carry a small, tightly
# matched set of non-surfacing exemptions so the operator's real workflow
# (dotenv-load, ssh -i key, ls of a secrets dir) is never blocked. A pure
# path-only block was measured against 4200+ logged commands: it would have
# blocked 47 legitimate ones, so the exemptions are load-bearing, not cosmetic.

# cmd_names_secret <string>: a credential CONTENT path is named. The
# .env.example / .env.template / .env.sample family is stripped FIRST so it can
# no longer mask a real read - `cat .env.example secrets/.env` used to disable
# the whole check because ".env.example" appeared somewhere in it.
cmd_names_secret() {
  local s="$1"
  s="${s//.env.example/__EX__}"
  s="${s//.env.template/__EX__}"
  s="${s//.env.sample/__EX__}"
  s="${s//env.template/__EX__}"
  # .env as a token, not .environment / .envrc
  [[ "$s" =~ \.env([^A-Za-z0-9_-]|$) ]] && return 0
  case "$s" in
    *secrets/*|*/.ssh/*|*.git-credentials*|*/.aws/*|*/.gnupg/*|\
    */.netrc*|*/.npmrc*|*/.config/gcloud/*|*/run/aios/*) return 0 ;;
  esac
  # .pem / .key as path tokens (not "monkey" etc.)
  [[ "$s" =~ \.pem([^A-Za-z0-9_-]|$) ]] && return 0
  [[ "$s" =~ \.key([^A-Za-z0-9_-]|$) ]] && return 0
  return 1
}

# cmd_has_read_verb <string>: a read/copy verb, aliases included. Used ONLY in
# the ssh/scp remote branch of 1b (narrow), where local path-based blocking
# would over-block a plain remote `ls`.
cmd_has_read_verb() {
  local s="$1"
  case "$s" in
    *"cat "*|*"type "*|*"tac "*|*"nl "*|*"Get-Content"*|*"gc "*|*"head "*|*"tail "*|\
    *"more "*|*"less "*|*"grep "*|*"egrep "*|*"fgrep "*|*"rg "*|*"findstr"*|\
    *"Select-String"*|*"sls "*|*"awk "*|*"sed "*|*"cut "*|*"od "*|*"xxd "*|\
    *"strings "*|*"dd "*|*"base64 "*|*"cp "*|*"copy "*|*"Copy-Item"*|*"scp "*|\
    *"ReadAllText"*|*"ReadAllLines"*|*"ReadAllBytes"*) return 0 ;;
  esac
  return 1
}

# secret_use_is_safe <string>: TRUE only for shapes that provably do NOT surface
# a local secret's bytes into the model's context.
secret_use_is_safe() {
  local s="$1" t first base
  # (E1) metadata-only: a lister/stat leads, and there is no pipe, chain, or
  #      command substitution (any of which could feed the path into a reader -
  #      `ls secrets/ | xargs cat` must NOT be exempt). Redirects are fine: the
  #      leading verb only emits metadata.
  if [[ "$s" != *"|"* && "$s" != *";"* && "$s" != *"&&"* && "$s" != *"||"* && \
        "$s" != *'$('* && "$s" != *'`'* && "$s" != *$'\n'* ]]; then
    case "$s" in
      ls|ls\ *|dir\ *|stat\ *|test\ *|\[\ *|Test-Path*|Get-Item\ *|gi\ *|\
      Get-ChildItem*|gci\ *|file\ *|du\ *|git\ check-ignore*|git\ ls-files*|\
      git\ status*)
        return 0 ;;
      find\ *)
        [[ "$s" == *"-exec"* || "$s" == *"-delete"* || "$s" == *"-execdir"* ]] || return 0 ;;
    esac
  fi
  # (E2) an inline / script interpreter leads: the code-execution lane, out of
  #      1b's scope by design. Blocking every interpreter that merely NAMES a
  #      secret path breaks the operator's dotenv-load workflow (load_dotenv,
  #      token surgery, the demo collectors). This is unchanged from before -
  #      `python -c open(...).read()` already walked past the old 1b too - it is
  #      just made explicit. NOTE the residual: a hijacked interpreter can still
  #      read; that is the code-execution-lane problem, tracked separately.
  #      powershell/pwsh are deliberately NOT here, so `powershell -c Get-Content
  #      secret` still blocks.
  t="$s"
  while [[ "$t" =~ ^[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]* ]]; do
    t="${t#*[[:space:]]}"
    [[ "$t" == "$s" ]] && break
  done
  first="${t%%[[:space:]]*}"; base="${first##*/}"
  case "$base" in
    python|python3|py|python.exe|pythonw.exe|python3.exe|node|node.exe|nodejs|\
    deno|deno.exe|ruby|ruby.exe|perl|perl.exe|php|php.exe|Rscript|Rscript.exe|bun)
      return 0 ;;
  esac
  return 1
}

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

# 1b. Same secret paths named inside a COMMAND (a command like `cat secrets/.env`
#     carries no file_path field). Verb-INDEPENDENT since 2026-09-04: naming a
#     credential CONTENT path blocks, unless the command is a proven
#     non-surfacing shape (metadata-only, or an inline/script interpreter - see
#     secret_use_is_safe). The ssh/scp/rsync family is handled separately so a
#     `-i key` auth use and a plain remote `ls` are not hard-blocked, while a
#     transfer of the secret itself still is.
if [ -n "$CMD" ] && cmd_names_secret "$CMD_N"; then
  case "$CMD_N" in
    ssh\ *|*" ssh "*|scp\ *|*" scp "*|sftp\ *|*" sftp "*|rsync\ *|*" rsync "*)
      # Strip identity material (.ssh/.pem/.key); what remains is a real content
      # path used as a source or a remote target.
      RES="$CMD_N"; RES="${RES//.ssh\//}"
      RES="${RES//.pem/}"; RES="${RES//.key/}"
      if cmd_names_secret "$RES"; then
        case "$CMD_N" in
          scp\ *|*" scp "*|sftp\ *|*" sftp "*|rsync\ *|*" rsync "*)
            block "Security floor: copying a credential file to another machine is blocked." ;;
          *)  # ssh remote command: a read verb surfaces the remote secret; a
              # plain remote ls falls through to section 6 (ask).
            if cmd_has_read_verb "$RES"; then
              block "Security floor: reading a credential file through a command is blocked."
            fi ;;
        esac
      fi
      ;;
    *)
      if ! secret_use_is_safe "$CMD_N"; then
        block "Security floor: reading or copying credential files through a command is blocked."
      fi
      ;;
  esac
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
  # Destroy/overwrite of a protected path. Verb list widened 2026-09-04 to the
  # aliases the old form missed (ri/rd/rmdir/erase/unlink, mi/move, clc), the
  # overwrite verbs (Set-Content/Out-File/Clear-Content), a truncating `>`, and
  # the .NET methods ([IO.File]::Delete, [IO.Directory]::Delete, WriteAllText).
  # Verbs are matched at a word boundary so `word `/`stri ng` cannot false-fire.
  if [[ "$CMD_N" == *"/secrets"* || "$CMD_N" == *"secrets/"* || "$CMD_N" == *"/memory"* || \
        "$CMD_N" == *"memory/"* || "$CMD_N" == *".claude/projects"* || "$CMD_N" == *"/.env"* ]]; then
    # A truncating `>` into a SECRET path is already caught by 1b (it names the
    # secret and no non-surfacing exemption applies), so this section only needs
    # the delete/move/overwrite verbs and .NET methods.
    if [[ "$CMD_N" =~ (^|[;\&\|[:space:]\(])(rm|del|erase|unlink|ri|rd|rmdir|mv|move|mi|Remove-Item|Move-Item|Clear-Content|clc|Set-Content|sc|Out-File)([[:space:]]|$) ]] || \
       [[ "$CMD_N" == *"::Delete("* || "$CMD_N" == *"WriteAllText"* || "$CMD_N" == *"WriteAllBytes"* ]]; then
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
# CONTENT-VS-TARGET HELPERS (added 2026-09-04 late, guard v1.6.0)
#
#    A rule that scans the raw command string cannot tell a protected thing
#    NAMED AS CONTENT (a commit message, a heredoc body, a grep pattern, a
#    note) from one being ACTED ON. These helpers turn the command into a
#    SKELETON and STAGES so sections 4 and 5 can ask "is the protected thing
#    in the stage that acts on it" instead of "does the string contain it".
#
#    Every exemption is provable from shell semantics. Anything the helpers
#    cannot classify - command substitution, a variable or unknown verb in
#    the acting position, a body piped into an interpreter, a very long
#    command - falls back to the old whole-string rule: conservative, never
#    a silent allow.
#
#    * skeleton: a heredoc body (<<TAG ... TAG) or PowerShell here-string
#      (@' ... '@) is removed ONLY when the stage that owns it is a content
#      verb (cat, printf, git commit ...) and nothing downstream in that
#      pipeline can execute the body. `bash <<EOF`, `python - <<EOF`,
#      `cat <<EOF | sh`, `$x = @'...'@`, and an unquoted tag whose body
#      carries $( ) are never stripped.
#    * stages: split on ; && || | and newline, quote-aware. A stage's
#      leading verb (after sudo/env/VAR= prefixes) is CONTENT if it provably
#      only reads or emits: echo printf cat head tail grep rg diff stat ls
#      Get-* Test-* ... plus `git` read subcommands (status log show diff
#      commit add ...). `sed -i`, `sort -o`, `find -exec`, `rg --pre`, a
#      sed/awk whose QUOTED script names the path, and every interpreter
#      with -c/-e are NOT content. `bash <gated script>` / `node <gated
#      script>` with no other gated token IS content (running the guard or
#      the watcher is a read of it).
#    * redirects are scanned over the whole skeleton, quote-aware, so a
#      content verb whose output lands IN a gated file still blocks.
# =========================================================================

# targets_gate <string>: names a self-protection target. Defined here (not in
# section 4) because the helpers below call it while the skeleton is built.
#   2026-09-01 (P0 of the escape-route pass): four more files that grant
#   persistence sat outside this gate - settings.local.json (allow rules
#   remove the human prompt), .mcp.json and ~/.claude.json (an MCP server =
#   code execution at next start), and command/floor (the bot-lane copy of
#   this very file, loaded via --settings for every headless spawn).
targets_gate() {
  [[ "$1" == *".claude/hooks"* || "$1" == *".claude/settings.json"* || "$1" == *".claude/plugins"* || \
     "$1" == *".claude/settings.local.json"* || "$1" == *".mcp.json"* || "$1" == *".claude.json"* || \
     "$1" == *"command/floor"* ]]
}

# Regexes that carry quote characters live in variables so [[ =~ ]] never has
# to parse a quote or a > as shell syntax.
RX_QUOTED="('[^']*'|\"[^\"]*\")"
RX_REDIR="(>>|>\\||&>|[0-9]?>)[[:space:]]*(\"[^\"]*\"|'[^']*'|[^[:space:];|&)]+)"
RX_PS_ASSIGN='^\$[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[^=]'
RX_INTERP_FLAG='(^|[[:space:]])-[A-Za-z]*[cesp]([[:space:]]|$)'
RX_STDIN_DASH='(^|[[:space:]])-([[:space:]]|$)'
RX_SORT_OUT='(^|[[:space:]])(-o|--output)([[:space:]=]|$)'
RX_SED_INPLACE='(^|[[:space:]])-[A-Za-z]*i'

# unescape_cmd <raw command>: JSON escapes -> real characters, Windows
# separators -> slash (the same mapping the normalizer above uses), doubled
# slashes collapsed. The result carries REAL newlines for the stage splitter.
unescape_cmd() {
  local s="$1"
  s="${s//\\\\\\n/ }"                 # backslash-newline continuation -> join
  s="${s//\\\\/$'\001'}"
  s="${s//\\n/$'\n'}"
  s="${s//\\r/}"
  s="${s//\\t/ }"
  s="${s//$'\001'//}"
  s="${s//\\//}"
  while [[ "$s" == *"//"* ]]; do s="${s//\/\//\/}"; done
  printf '%s' "$s"
}

# stage_verb <stage>: the leading verb after sudo/env/time/nohup/exec and
# VAR=value prefixes; basename only (.venv/Scripts/python.exe -> python.exe).
# A PowerShell assignment ($x = verb ...) yields the RHS verb - the variable
# only receives what the verb produces; its later use is its own stage.
stage_verb() {
  local t="$1" w
  while [[ "$t" == [[:space:]\(\{]* ]]; do t="${t:1}"; done
  if [[ "$t" =~ $RX_PS_ASSIGN ]]; then
    t="${t#*=}"; while [[ "$t" == [[:space:]\(\{]* ]]; do t="${t:1}"; done
  fi
  while :; do
    w="${t%%[[:space:]]*}"
    case "$w" in
      sudo|env|time|nohup|exec|command|builtin|nice) ;;
      *) if [[ "$w" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then :; else break; fi ;;
    esac
    [[ "$t" == *[[:space:]]* ]] || { t=""; break; }
    t="${t#*[[:space:]]}"; while [[ "$t" == [[:space:]]* ]]; do t="${t:1}"; done
  done
  w="${t%%[[:space:]]*}"; w="${w##*/}"
  printf '%s' "$w"
}

# quoted_names_gate <stage>: 0 if any '...' or "..." string in the stage
# names a gated path (a sed/awk script or an interpreter string can act on
# what it names; a bare argument to a reader is only read).
quoted_names_gate() {
  local s="$1"
  while [[ "$s" =~ $RX_QUOTED ]]; do
    targets_gate "${BASH_REMATCH[1]}" && return 0
    s="${s#*"${BASH_REMATCH[1]}"}"
  done
  return 1
}

# git_read_subcmd <stage>: 0 if the git subcommand only reads the tree or
# writes the index/object store (never a working-tree file it was given).
git_read_subcmd() {
  local seen=0 skipnext=0 tok sub="" toks
  read -ra toks <<< "$1"
  for tok in "${toks[@]}"; do
    if [ "$seen" -eq 0 ]; then
      case "${tok##*/}" in git|git.exe) seen=1 ;; esac
      continue
    fi
    if [ "$skipnext" -eq 1 ]; then skipnext=0; continue; fi
    case "$tok" in
      -C|-c|--git-dir|--work-tree|--exec-path|--namespace) skipnext=1; continue ;;
      -*) continue ;;
    esac
    sub="$tok"; break
  done
  case "$sub" in
    status|log|show|diff|grep|ls-files|ls-tree|check-ignore|blame|rev-parse|cat-file|\
    hash-object|describe|shortlog|reflog|commit|add|tag|notes|remote|fetch|branch|var|\
    help|version|count-objects|for-each-ref|show-ref|name-rev|whatchanged|range-diff|\
    cherry|merge-base|rev-list|verify-commit|verify-tag|diff-tree|diff-index|check-attr)
      return 0 ;;
  esac
  return 1
}

# content_verb <verb> <stage>: 0 if this stage provably only reads or emits.
content_verb() {
  local v="$1" st="$2" tok first="" rest toks
  case "$v" in
    echo|printf|cat|type|head|tail|less|more|wc|diff|cmp|comm|nl|tac|od|hexdump|strings|\
    sha256sum|sha1sum|md5sum|shasum|cksum|b2sum|grep|egrep|fgrep|findstr|cut|uniq|tr|file|\
    tree|du|ls|dir|stat|test|\[|readlink|realpath|basename|dirname|which|pwd|true|false|\
    Get-*|Test-*|gc|gi|gci|gp|sls|Select-String|Compare-Object|compare|Measure-Object|measure|\
    Select-Object|select|Sort-Object|Group-Object|group|Format-*|fl|ft|fw|Out-String|\
    Out-Host|Out-Default|Write-Output|Write-Host|Write-Verbose|Write-Information|\
    Resolve-Path|rvpa|Split-Path|Join-Path|ConvertTo-Json|ConvertFrom-Json|Write-Error)
      return 0 ;;
    rg)    [[ "$st" == *"--pre"* ]] && return 1; return 0 ;;
    sort)  [[ "$st" =~ $RX_SORT_OUT ]] && return 1; return 0 ;;
    sed)   [[ "$st" =~ $RX_SED_INPLACE || "$st" == *"--in-place"* ]] && return 1
           quoted_names_gate "$st" && return 1; return 0 ;;
    awk|gawk|mawk)
           quoted_names_gate "$st" && return 1; return 0 ;;
    find)  [[ "$st" == *"-exec"* || "$st" == *"-delete"* || "$st" == *"-ok"* || \
              "$st" == *"-fprint"* ]] && return 1; return 0 ;;
    git)   git_read_subcmd "$st"; return ;;
    bash|sh|zsh|dash|node|node.exe)
           # running a script that lives in a gated dir (the guard, the
           # watcher) reads it; a -c/-e string or a stdin script is the
           # interpreter lane and stays conservative.
           [[ "$st" =~ $RX_INTERP_FLAG || "$st" == *"--eval"* || \
              "$st" == *"<<"* || "$st" =~ $RX_STDIN_DASH ]] && return 1
           read -ra toks <<< "$st"
           for tok in "${toks[@]}"; do
             case "${tok##*/}" in bash|sh|zsh|dash|node|node.exe) continue ;; esac
             case "$tok" in -*) continue ;; esac
             first="$tok"; break
           done
           [ -n "$first" ] || return 1
           rest="${st/"$first"/}"
           targets_gate "$rest" && return 1
           return 0 ;;
  esac
  return 1
}

# split_stages <skeleton>: fills STAGES[] (text), STAGE_PID[] (pipeline
# index), STAGE_PIPED[] (1 = fed by a pipe), PIPE_TEXT[] (whole pipeline).
# Quote-aware: | ; && || and newline split only outside quotes.
split_stages() {
  # NOTE: n must be declared on its own line - in one `local a=$1 n=${#a}`
  # the ${#a} expands BEFORE a is assigned (bash expands every word first),
  # so n was 0 and every command became a single empty stage. Caught by the
  # battery on the first run of this code (8 section-5/4 cases went quiet).
  local s="$1" i c q="" cur="" pid=0 piped=0
  local n=${#s}
  STAGES=(); STAGE_PID=(); STAGE_PIPED=(); PIPE_TEXT=()
  _push() {
    STAGES+=("$cur"); STAGE_PID+=("$pid"); STAGE_PIPED+=("$piped")
    PIPE_TEXT[$pid]="${PIPE_TEXT[$pid]:-}$cur"
  }
  for (( i=0; i<n; i++ )); do
    c="${s:i:1}"
    if [ -n "$q" ]; then
      cur+="$c"; [ "$c" = "$q" ] && q=""
      continue
    fi
    case "$c" in
      \'|\") q="$c"; cur+="$c" ;;
      "|") _push
           if [ "${s:i+1:1}" = "|" ]; then pid=$((pid+1)); piped=0; i=$((i+1)); else piped=1; fi
           cur="" ;;
      "&") if [ "${s:i+1:1}" = "&" ]; then _push; pid=$((pid+1)); piped=0; i=$((i+1)); cur=""
           else cur+="$c"; fi ;;
      ";"|$'\n') _push; pid=$((pid+1)); piped=0; cur="" ;;
      *) cur+="$c" ;;
    esac
  done
  _push
}

# strip_bodies <unescaped command>: remove heredoc / here-string BODIES that
# are provably content. Unterminated, interpreter-owned, piped-onward, or
# expandable ($( ) under an unquoted tag) bodies are left in place.
strip_bodies() {
  local s="$1" out="" m tag quoted rest lrest after body own lastsep stg v ok
  while [[ "$s" =~ \<\<-?[[:space:]]*(\'|\")?([A-Za-z_][A-Za-z0-9_]*)(\'|\")? ]]; do
    m="${BASH_REMATCH[0]}"; tag="${BASH_REMATCH[2]}"; quoted="${BASH_REMATCH[1]}"
    own="${s%%"$m"*}"; rest="${s#*"$m"}"
    if [[ "$own" == *"<" ]] || [[ "$rest" != *$'\n'* ]]; then
      out="$out$own$m"; s="$rest"; continue            # here-string / no body
    fi
    lrest="${rest%%$'\n'*}"; after="${rest#*$'\n'}"
    if [[ "$after" == "$tag" ]]; then body=""; s=""
    elif [[ "$after" == "$tag"$'\n'* ]]; then body=""; s="${after#"$tag"$'\n'}"
    elif [[ "$after" == *$'\n'"$tag"$'\n'* ]]; then body="${after%%$'\n'"$tag"$'\n'*}"; s="${after#*$'\n'"$tag"$'\n'}"
    elif [[ "$after" == *$'\n'"$tag" ]]; then body="${after%$'\n'"$tag"}"; s=""
    else out="$out$own$m$rest"; s=""; break               # unterminated: keep all
    fi
    # the owning stage: text after the last separator on the operator's line,
    # plus the rest of that line. Content verb required, nothing downstream.
    stg="$own"
    while [[ "$stg" == *$'\n'* ]]; do stg="${stg#*$'\n'}"; done
    while [[ "$stg" == *";"* ]]; do stg="${stg#*;}"; done
    while [[ "$stg" == *"&&"* ]]; do stg="${stg#*&&}"; done
    while [[ "$stg" == *"||"* ]]; do stg="${stg#*||}"; done
    while [[ "$stg" == *"|"* ]]; do stg="${stg#*|}"; done
    v=$(stage_verb "$stg")
    ok=0
    if content_verb "$v" "$stg $lrest"; then
      ok=1
      [[ "$lrest" == *"|"* ]] && ok=0                        # body piped onward
      [[ -z "$quoted" && ( "$body" == *'$('* || "$body" == *'`'* ) ]] && ok=0
    fi
    if [ "$ok" -eq 1 ]; then
      out="$out$own$m$lrest"$'\n'
    else
      out="$out$own$m$lrest"$'\n'"$body"$'\n'"$tag"$'\n'
    fi
  done
  s="$out$s"
  # PowerShell here-strings: only a content-verb owner is stripped.
  local qch pre
  for qch in "'" '"'; do
    out=""
    while [[ "$s" == *"@$qch"* ]]; do
      pre="${s%%"@$qch"*}"; rest="${s#*"@$qch"}"
      if [[ "$rest" != *"$qch@"* ]]; then break; fi
      body="${rest%%"$qch@"*}"
      stg="$pre"
      while [[ "$stg" == *$'\n'* ]]; do stg="${stg#*$'\n'}"; done
      while [[ "$stg" == *";"* ]]; do stg="${stg#*;}"; done
      while [[ "$stg" == *"|"* ]]; do stg="${stg#*|}"; done
      v=$(stage_verb "$stg")
      if content_verb "$v" "$stg" && [[ "$stg" != *'$'*=* ]]; then
        out="$out$pre@$qch$qch@"
      else
        out="$out$pre@$qch$body$qch@"
      fi
      s="${rest#*"$qch@"}"
    done
    s="$out$s"
  done
  printf '%s' "$s"
}

# redirect_targets_hit <skeleton>: 0 if any redirect writes into a gated path.
# Sets REDIR_UNKNOWN=1 when a redirect target is a variable (unclassifiable).
REDIR_UNKNOWN=0
redirect_targets_hit() {
  local s="$1" tgt
  REDIR_UNKNOWN=0
  while [[ "$s" =~ $RX_REDIR ]]; do
    tgt="${BASH_REMATCH[2]}"
    s="${s#*"${BASH_REMATCH[0]}"}"
    tgt="${tgt#[\"\']}"; tgt="${tgt%[\"\']}"
    case "$tgt" in /dev/null|nul|NUL|/dev/stderr|/dev/stdout) continue ;; esac
    [[ "$tgt" == *'$'* ]] && REDIR_UNKNOWN=1
    targets_gate "$tgt" && return 0
  done
  return 1
}

# The command skeleton, built once. SK carries real newlines and no
# backslashes; SK_BIG marks a command too long to classify cheaply.
SK=""; SK_BIG=0
if [ -n "$CMD" ]; then
  SK=$(unescape_cmd "$CMD")
  if [ "${#SK}" -gt 20000 ]; then SK_BIG=1; else SK=$(strip_bodies "$SK"); fi
fi
# unclassifiable <skeleton>: shapes the stage logic must not reason about.
unclassifiable() {
  # $( ) and backticks run code; ${ } can hold a path the stage logic cannot
  # see; <( ) and >( ) process substitution runs code too (`diff <(rm x)`).
  [ "$SK_BIG" -eq 1 ] || [[ "$1" == *'$('* || "$1" == *'`'* || "$1" == *'${'* || \
                           "$1" == *'<('* || "$1" == *'>('* ]]
}

# =========================================================================
# 4. GATE TAMPERING - with a maintenance escape hatch
#
#    Blocks the assistant from rewriting its own gate on a single instruction
#    (the prompt-injection case). Does NOT lock anyone out: the operator (or
#    the client, deliberately) touches the sentinel FROM THEIR OWN TERMINAL,
#    then edits within 15 min.
#
#      touch <workspace>/.claude/hooks/.maintenance      (Git Bash)
#      New-Item <workspace>\.claude\hooks\.maintenance   (PowerShell)
#      (plugin-carried guard: touch .maintenance beside the cached hook;
#       .claude/plugins is gated too since v1.2.0, 2026-08-21)
#
#    Two deliberate steps beats one injected instruction - which is only true
#    if step one needs a human. Section 4a (2026-09-02) makes it so: the
#    assistant cannot create the sentinel through any tool.
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

# targets_gate() - the list of self-protection targets - is defined with the
# content-vs-target helpers above section 4 (v1.6.0), unchanged in content.

# 4a. The sentinel itself (added 2026-09-02). `touch`, `New-Item` and `echo`
#     were not write verbs, so the assistant could open its own window and
#     edit the gate in the same turn (verified by behavior). Any tool call that
#     names the sentinel is treated as a write unless it is a Read/Glob/Grep,
#     or a bare read-only command shape (ls / stat / test / Test-Path /
#     Get-Item) with no chaining, piping or substitution. There is no allowed
#     way to create, touch, copy or write it through the assistant.
# 4a-refined 2026-09-04: only fire when the sentinel is a TARGET, not when its
#   name merely appears as content. The old trigger fired on ANY mention, so a
#   commit message, a note, or a heredoc that quoted ".maintenance" was blocked.
#   Now: the Write/Edit file_path names it, OR a real path token (/.maintenance)
#   sits in the command skeleton (heredoc bodies stripped, so a documented
#   command is not a target), OR a create/write/delete verb targets a
#   .maintenance filename directly (quoted or bare), OR a redirect writes into
#   one. A prose mention (`.maintenance` after a space, no separator, no verb)
#   no longer fires. Writing INTO the sentinel still does.
MAINT_TRIG=0
[[ "$FILE" == *".maintenance"* ]] && MAINT_TRIG=1
if [ -n "$CMD" ]; then
  # A TARGET is: a real path token to the sentinel (/.maintenance), a create/
  # write/delete verb naming a .maintenance filename directly (quoted or bare),
  # or a redirect writing into one. A bare prose mention - the name after a
  # space with no separator and no verb, as in a commit message or a note - is
  # NOT a target and no longer fires. NOTE: a heredoc/string that literally
  # contains a `.../.maintenance` path is still treated conservatively as a
  # target; write such runbooks with the Write/Edit tools (those never reach
  # this command path).
  MAINT_VRX='(^|[^A-Za-z0-9_.])(touch|New-Item|ni|echo|printf|tee|cp|copy|mv|move|rm|del|ri|Set-Content|sc|Out-File|Add-Content)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*[^[:space:]]*\.maintenance'
  if [[ "$CMD_N" == *"/.maintenance"* ]] || \
     [[ "$CMD_N" =~ $MAINT_VRX ]] || \
     [[ "$CMD_N" =~ \>[[:space:]]*[^[:space:]]*\.maintenance ]]; then
    MAINT_TRIG=1
  fi
fi
if [ "$MAINT_TRIG" -eq 1 ]; then
  MAINT_OK=0
  if [[ "$TOOL" == "Read" || "$TOOL" == "Glob" || "$TOOL" == "Grep" ]]; then
    MAINT_OK=1
  elif [ -z "$FILE" ] && [ -n "$CMD" ]; then
    if [[ "$CMD_N" != *";"* && "$CMD_N" != *"&&"* && "$CMD_N" != *"||"* && "$CMD_N" != *"|"* && \
          "$CMD_N" != *'$('* && "$CMD_N" != *'`'* && "$CMD_N" != *$'\n'* && "$CMD_N" != *"\\n"* ]]; then
      case "$CMD_N" in
        ls|ls\ *|stat\ *|test\ *|\[\ *|Test-Path*|Get-Item\ *) MAINT_OK=1 ;;
      esac
    fi
  fi
  if [ "$MAINT_OK" -eq 0 ]; then
    block "Security floor: the maintenance sentinel is created by a person from their own terminal (PowerShell or Git Bash), never through the assistant. Create .maintenance beside security-guard.sh yourself, then retry within 15 minutes."
  fi
fi

# gate_write_old <skeleton>: the pre-v1.6.0 whole-string rule (a gated path
# anywhere + a write verb or redirect anywhere), kept as the conservative
# fallback for shapes the stage logic will not reason about. The verb list is
# a little wider than 1.5.0's (ln/chmod/dd/install/truncate, the PowerShell
# item cmdlets, the .NET writers) - widening a fallback only ever blocks more.
gate_write_old() {
  local w="$1"
  w="${w//2>&1/}"; w="${w//2>\/dev\/null/}"; w="${w//>\/dev\/null/}"
  [[ "$w" == *">"* ]] && return 0
  [[ "$1" =~ (^|[[:space:]\;\&\|\(])(cp|mv|tee|rm|ln|chmod|chown|dd|install|truncate|rmdir|ri|rd|del|mi|move|copy)([[:space:]]|$) ]] && return 0
  [[ "$1" == *"sed -i"* || "$1" == *"Set-Content"* || "$1" == *"Out-File"* || "$1" == *"Add-Content"* || \
     "$1" == *"Copy-Item"* || "$1" == *"Move-Item"* || "$1" == *"Remove-Item"* || "$1" == *"Rename-Item"* || \
     "$1" == *"New-Item"* || "$1" == *"Clear-Content"* || "$1" == *"WriteAll"* || "$1" == *"::Copy("* || \
     "$1" == *"::Move("* || "$1" == *"::Delete("* || "$1" == *"AppendAll"* ]] && return 0
  return 1
}

# gate_write <skeleton>: 0 when a gated path is a write TARGET of this
# command - or when the command cannot be classified. Reads of a gated file
# (cat, diff, sha256sum, git show, running the guard) return 1: reads stay
# allowed, as they always were.
gate_write() {
  local sk="$1" i pid v
  targets_gate "$sk" || return 1
  if unclassifiable "$sk"; then gate_write_old "$sk"; return; fi
  redirect_targets_hit "$sk" && return 0
  if [ "$REDIR_UNKNOWN" -eq 1 ]; then gate_write_old "$sk"; return; fi
  split_stages "$sk"
  for (( i=0; i<${#STAGES[@]}; i++ )); do
    pid="${STAGE_PID[$i]}"
    targets_gate "${PIPE_TEXT[$pid]}" || continue
    v=$(stage_verb "${STAGES[$i]}")
    content_verb "$v" "${STAGES[$i]}" || return 0
  done
  return 1
}

# The gate itself. File tools: a write tool on a gated path. Commands: the
# skeleton/stage reasoning above (v1.6.0) - a heredoc commit body that
# mentions command/floor, a grep for ".claude/hooks", an echo of a note that
# names settings.json into an ordinary file all pass now; a cp/tee/redirect
# INTO a gated path, a cd into a gated dir followed by anything, a
# non-content verb naming a gated path, a stage fed by a pipe from a gated
# listing, or a heredoc piped into a shell all still block.
WRITEISH=0
if [[ "$TOOL" == "Edit" || "$TOOL" == "Write" || "$TOOL" == "NotebookEdit" ]] && targets_gate "$FILE"; then
  WRITEISH=1
fi
if [ -n "$CMD" ] && gate_write "$SK"; then
  WRITEISH=1
fi
if [ "$WRITEISH" -eq 1 ] && ! maint_open; then
  block "Security floor: the gate protects itself (hooks, settings, settings.local, .mcp.json, .claude.json, plugins, command/floor). Reads through cat, git show, Get-Content or grep stay allowed; an interpreter, loop or copy naming one of these files counts as a write. To edit deliberately: from your OWN terminal, create a .maintenance file beside security-guard.sh, then retry within 15 minutes."
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
# floor_off_flag <string>: a flag or env form that starts a session without
# the settings layer (and so without this hook). 2026-09-04 late: `--bare`
# ("skip hooks, LSP, plugin sync ...") and `--plugin-url` (arbitrary hooks
# fetched from a URL) joined the list - both live in CLI 2.1.261, neither
# was gated. CLAUDE_CODE_SIMPLE=1 is what --bare sets, so the env form is
# gated too.
RX_BARE='--bare([[:space:]=]|$)'
floor_off_flag() {
  [[ "$1" == *"--safe-mode"* || "$1" == *"--restricted"* || "$1" == *"--setting-sources"* || \
     "$1" == *"--plugin-dir"* || "$1" == *"--plugin-url"* || "$1" == *"--settings "* || \
     "$1" == *"--settings="* || "$1" == *"CLAUDE_CONFIG_DIR="* || "$1" == *"CLAUDE_CODE_SIMPLE="* ]] || \
  [[ "$1" =~ $RX_BARE ]]
}
RX_CLAUDE_WORD='(^|[^A-Za-z0-9_.-])claude([^A-Za-z0-9_-]|$)'
names_claude() {
  [[ "$1" =~ $RX_CLAUDE_WORD ]] || [[ "$1" == *"CLAUDE_CONFIG_DIR="* || "$1" == *"CLAUDE_CODE_SIMPLE="* ]]
}
# The 1.5.0 space-delimited test, kept as the fallback for commands the stage
# logic will not reason about (command substitution etc.): identical to what
# shipped before, so an unclassifiable command decides exactly as 1.5.0 did.
names_claude_old() {
  [[ "$1" == "claude "* || "$1" == *" claude "* || "$1" == *"/claude "* || \
     "$1" == *$'\n'"claude "* || \
     "$1" == *"claude.exe"* || "$1" == *"claude.cmd"* || \
     "$1" == *"CLAUDE_CONFIG_DIR="* || "$1" == *"CLAUDE_CODE_SIMPLE="* ]]
}
if [ -n "$CMD" ]; then
  # names_claude is a word match, wider than 1.5.0's space-delimited test:
  # `bash -c "claude --bare"` and `c=claude; $c --bare` never matched before.
  if names_claude "$CMD_N" && floor_off_flag "$CMD_N"; then
    # 2026-09-04 late (content-vs-target): the flag must sit in a stage that
    # launches claude - the launch stage itself, an unclassifiable stage
    # (a variable or unknown verb in the acting position), or a content stage
    # that feeds a later claude stage through a pipe. `claude --help | grep
    # -- --safe-mode` and `echo "--bare" > notes.md; claude -p x` pass now;
    # `bash -c "claude --bare"`, `c=claude; $c --bare`, and `echo --bare |
    # xargs claude` still block. Unclassifiable commands block as before.
    LAUNCH_HIT=0
    if unclassifiable "$SK"; then
      names_claude_old "$CMD_N" && LAUNCH_HIT=1
    else
      split_stages "$SK"
      for (( i=0; i<${#STAGES[@]}; i++ )); do
        floor_off_flag "${STAGES[$i]}" || continue
        v=$(stage_verb "${STAGES[$i]}")
        if content_verb "$v" "${STAGES[$i]}"; then
          # a content stage (printf of a payload, echo of a note, grep of a
          # flag) launches nothing itself - only what it feeds can. Does a
          # later stage in the same pipeline launch claude?
          for (( j=i+1; j<${#STAGES[@]}; j++ )); do
            [ "${STAGE_PID[$j]}" = "${STAGE_PID[$i]}" ] || break
            if names_claude "${STAGES[$j]}"; then LAUNCH_HIT=1; break; fi
          done
        elif names_claude "${STAGES[$i]}"; then
          LAUNCH_HIT=1
        else
          LAUNCH_HIT=1      # a non-content, non-claude verb carrying the flag: unknown = launch
        fi
        [ "$LAUNCH_HIT" -eq 1 ] && break
      done
    fi
    if [ "$LAUNCH_HIT" -eq 1 ]; then
      block "Security floor: starting a nested Claude Code session with the floor switched off (--safe-mode, --restricted, --bare, --setting-sources, --settings, --plugin-dir, --plugin-url, a redirected config dir) is blocked. A plain nested claude -p is fine."
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
  # PowerShell/.NET and BITS upload shapes (added 2026-09-04, same verb-list gap
  # as 1b): [Net.WebClient]::UploadFile/UploadData/UploadString, and
  # Start-BitsTransfer -TransferType Upload.
  if [[ "$CMD_N" == *"UploadFile"* || "$CMD_N" == *"UploadData"* || \
        "$CMD_N" == *"UploadString"* || "$CMD_N" == *"-TransferType Upload"* ]]; then
    OUTBOUND=1
  fi
  if [[ "$CMD_N" == *"scp "* || "$CMD_N" == *"rsync "* || "$CMD_N" == *"sftp "* ]] && \
     [[ "$CMD_N" == *"@"* && "$CMD_N" == *":"* ]]; then
    OUTBOUND=1
  fi
  if [ "$OUTBOUND" -eq 1 ]; then
    ask "Security floor: this command sends a file to another machine. Approve only if you meant to send it."
  fi
  # A network verb that names a credential-shaped path asks even with no file
  # body. Credential detection is token-scoped now (cmd_names_secret, which
  # strips .env.example first) plus a bare "credentials" - the old inline test
  # let ".env.example" disable the whole ask.
  if [[ "$CMD_N" == *"curl"* || "$CMD_N" == *"wget"* || "$CMD_N" == *"Invoke-RestMethod"* || \
        "$CMD_N" == *"Invoke-WebRequest"* || "$CMD_N" == *"irm "* || "$CMD_N" == *"iwr "* || \
        "$CMD_N" == *"UploadFile"* || "$CMD_N" == *"scp "* || "$CMD_N" == *"rsync "* || \
        "$CMD_N" == *"ssh "* || "$CMD_N" == *"nc "* || "$CMD_N" == *"ncat "* ]]; then
    if cmd_names_secret "$CMD_N" || { [[ "$CMD_N" == *"credentials"* ]] && [[ "$CMD_N" != *".env.example"* ]]; }; then
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

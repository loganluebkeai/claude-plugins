# Changelog - TrueNorth AIOS Security Floor

One line per release. The plugin's `version` in plugin.json is the update
signal; refresh with `/plugin marketplace update truenorth`.

- **1.6.0** (2026-09-04): Content-vs-target pass, plus two floor-off flags.
  A rule that scans the raw command string cannot tell a protected path
  NAMED AS CONTENT (a commit message, a heredoc body, a grep pattern, a note)
  from one being ACTED ON; found live twice the same day (a heredoc commit
  body mentioning `command/floor` blocked as a write to it; `claude --help |
  grep -- --safe-mode` blocked as a nested launch). Sections 4 and 5 now
  reason over a command skeleton and its pipeline stages: a heredoc body is
  stripped only when a content verb owns it and nothing downstream can run
  it; a stage's leading verb must provably only read or emit for the naming
  to be content; redirect targets are scanned quote-aware; anything
  unclassifiable (command substitution, a variable in the acting position, a
  body piped into a shell) falls back to the old whole-string rule. Reads of
  protected files stay allowed. The stage rule also closes writes 1.5.0 let
  through - `python -c`/`node -e` writing a hook, `chmod -x`, `ln -sf`,
  `curl -o`, `sort -o`, `sed w`, `git checkout --` on a protected file,
  `Copy-Item` into the plugin cache - and section 5 now sees
  `bash -c "claude --bare"` and `c=claude; $c --safe-mode`. New in section 5:
  `--bare` ("skip hooks ..." - the floor off by another name), `--plugin-url`
  (arbitrary hooks fetched from a URL) and the `CLAUDE_CODE_SIMPLE=` env form,
  all present in CLI 2.1.261 and none gated before. `verify-floor.sh` ships
  in the plugin root: one command proves a guard copy by behavior, tagged by
  the release each probe belongs to (`--all` checks every copy on the
  machine). The guard carries a `GUARD_VERSION` line the plugin battery
  asserts against `plugin.json`. Found by replaying 4149 unique logged
  operator commands (30 days) through 1.5.0 and this build and reading every
  changed decision: the JSON newline escape had been normalizing to the two
  characters `/n` since the Windows-path mapping was added, so every command
  on a line after the first was glued to the letter n - a line-start
  `rm -rf secrets/` missed section 3, `ls secrets/` + newline + `cat
  secrets/.env` passed section 1b's metadata exemption, `claude --safe-mode`
  on its own line was never seen by section 5, and a `cat` on a new line read
  as the `ncat` network verb (a false ask). Newlines are real newlines now
  and backslash-newline continuations are joined; four planted cases against
  every earlier release. Battery: 232 cases (was 164).
- **1.5.0** (2026-09-04, never published separately - folded into 1.6.0):
  Verb-independence pass. Section 1b matched a FIXED
  LIST of read verbs, so PowerShell aliases (`gc`, `sls`), .NET file methods
  (`[IO.File]::ReadAllText`), and a pipe (`ls secrets/ | xargs cat`) each read a
  credential straight past it (verified by behavior). 1b now gates on the
  invariant - a credential path is named - and blocks unless the command is a
  proven non-surfacing shape (metadata-only, an inline/script interpreter, or
  ssh/scp using key material only as the identity). Those exemptions were
  measured against 4200+ logged commands so the operator's real workflow
  (`load_dotenv`, `ssh -i key`, `ls` of a secrets dir) is never blocked; a pure
  path-only block would have hit 47 legitimate commands. The `.env.example` /
  `.env.template` exception is token-scoped - naming it anywhere used to disable
  the whole secret check (`cat .env.example secrets/.env` read the real file).
  Section 3 (delete) gained the alias/.NET verbs it missed (`ri`, `rd`,
  `rmdir`, `erase`, `Clear-Content`, `[IO.Directory]::Delete`); section 6
  (upload) gained the .NET/BITS shapes (`[Net.WebClient]::UploadFile`,
  `Start-BitsTransfer -TransferType Upload`), and uploading an actual secret
  file is now a hard BLOCK, not an ask (under bypass an ask is silent-allow).
  Section 4a fires only when the maintenance sentinel is a TARGET, not when its
  name merely appears in a commit message, note, or string. Battery: 164 cases
  (was 129); every new BLOCK case is a planted failure against 1.4.0.
- **1.4.0** (2026-09-02): Workspace-audit fixes, three bypasses each verified
  by behavior against 1.3.0. (1) Windows backslash paths un-gated the guard's
  self-protection: a JSON-escaped `C:\\x` normalized to `C://x`, so every
  gated pattern with an interior slash (`.claude/hooks`, `.claude/settings.json`,
  `.claude/settings.local.json`, `.claude/plugins`, `command/floor`) matched on
  forward-slash spellings only. Normalization now collapses the doubled
  slashes. (2) The maintenance sentinel could be created by the assistant
  (`touch` / `New-Item` / `echo` were not write verbs), collapsing the
  two-step ceremony into one turn; section 4a now treats any tool call that
  names `.maintenance` as a write unless it is a bare read-only shape - a
  person creates the sentinel from their own terminal. (3) Section 0 blocks
  code-execution tools by NAME (`python_repl`, `executeCode`, `run_command`)
  before any field is read; they carry `code`, not `command`, and walked past
  every check. Never fires on a zero-MCP client box. Battery: 129 cases (was
  89); every new BLOCK case is a planted failure against 1.3.0.
- **1.3.0** (2026-09-02): Escape-route pass. Section 5: a nested `claude`
  launch with the floor switched off (`--safe-mode`, `--restricted`,
  `--settings`, `--setting-sources`, `--plugin-dir`, or a `CLAUDE_CONFIG_DIR=`
  redirect) is blocked; plain `claude -p`, `--version` and `update` stay
  silent. Section 6: a file leaving the machine (curl/wget upload forms,
  `Invoke-RestMethod -InFile`, scp/rsync/sftp to a remote host) or a Gmail
  send/forward through the connector asks first - a real prompt in default
  and acceptEdits modes; under bypass it is not a prompt (bypass has opted
  out of prompts). Self-protection gate widened to `.claude/settings.local.json`,
  `.mcp.json` and `~/.claude.json`; `/run/aios/` joins the secret paths.
  Command extractor rewritten as an escape-aware walker (a quoted
  `curl -F "file=@x"` no longer hides its upload marker). Stderr redirects no
  longer count as writes. Battery: 89 cases.
- **1.2.0** (2026-08-21): Guard self-protection extended to the plugin cache -
  writes to `.claude/plugins` are blocked, with the same 15-minute
  `.maintenance` escape hatch the workspace gate uses.
- **1.1.0** (2026-08-21): Version watcher fixed for Windows npm installs (the
  no-shell process spawn could never resolve the installed version, so the
  watcher exited silently - since May, everywhere). An absent cache file now
  always means "never ran": unresolved-version runs leave a trace entry. Hook
  timeouts corrected to seconds (units confirmed by live probe).
- **1.0.1** (2026-08-20): First update pushed through the channel and verified
  by behavior on a second machine (cached hook: block exit 2 / benign exit 0).
- **1.0.0** (2026-08-20): Initial release - the 2026-08-12 security floor
  exactly: PreToolUse guard (blocks catastrophic-and-irreversible actions in
  every permission mode, including bypass) + Claude Code version watcher.

# Changelog - TrueNorth AIOS Security Floor

One line per release. The plugin's `version` in plugin.json is the update
signal; refresh with `/plugin marketplace update truenorth`.

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

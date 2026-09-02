# Changelog - TrueNorth AIOS Security Floor

One line per release. The plugin's `version` in plugin.json is the update
signal; refresh with `/plugin marketplace update truenorth`.

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

# Changelog - TrueNorth AIOS Security Floor

One line per release. The plugin's `version` in plugin.json is the update
signal; refresh with `/plugin marketplace update truenorth`.

- **1.6.1** (2026-09-24): The env spellings of the floor-off flags, and the
  Windows ways to set them. CLI 2.1.280 added `CLAUDE_CODE_PLUGIN_DIRS`,
  which loads every listed directory as a plugin exactly as `--plugin-dir`
  does; 1.6.0 blocked the flag and allowed `CLAUDE_CODE_PLUGIN_DIRS=<d>
  claude -p ...` (measured 9/23 on 2.1.281). Section 5 now gates it, plus
  `CLAUDE_CODE_SAFE_MODE` (a real child with it set loaded no plugins or
  hooks, measured 9/24) and `CLAUDE_CODE_RESTRICTED` (the twin of
  `--restricted`), the way it gates `CLAUDE_CONFIG_DIR=`: prefix, `export`,
  `env`, `cmd /c set`, a bash `+=`, and PowerShell's `$env:` / `${env:}`
  assignment with any spacing. Names match in any case (Windows env keys are
  case-insensitive; a lowercase key loaded a plugin, measured 9/24). The
  spaced PowerShell form, `+=` and `${env:}` were gaps 1.6.0 already had for
  `CLAUDE_CONFIG_DIR` and `CLAUDE_CODE_SIMPLE`. New section 5b: a gated name
  written through the Windows environment - the `env:` drive (`Set-Item`,
  `New-Item`, or any other verb or alias that is not a read or a remove),
  `[Environment]::SetEnvironmentVariable` at any scope, `setx`, the
  registry's `Environment` key - blocks whether or not the command launches
  anything, because the persisted forms reach every future session.
  Quiet: a plain read (`$env:NAME`, `Test-Path env:NAME`, `Get-Item
  env:NAME`, `Get-ItemProperty -Path HKCU:\Environment -Name NAME`, `dir
  env:NAME`, `Get-ChildItem env: | Where-Object Name -eq NAME`); grepping for
  it; a plain nested `claude -p`; code with a same-named variable assigned
  with spaces (`X = 1` in Python, a `[[ $X = y ]]` test, a PowerShell
  hashtable key); a commit message naming it, with `git commit -m "..."` or
  `git commit -F <file>`. Blocks, by design: an unspaced lowercase or
  snake_case assignment of a gated name (`claude_config_dir=...` in code), as
  the upper-case `NAME=` literal always has; a parenthesized read on the env
  drive or registry (`(Get-Item env:NAME).Value`, `if (Test-Path env:NAME)
  {..}`, `(Get-ItemProperty HKCU:\Environment).NAME`); a commit message
  built inside `$( )` (`-m "$(cat <<'EOF' ... EOF)"`) that also says
  `Environment`, `env:`, `setx` or `SetEnvironmentVariable` - write it to a
  file and use `git commit -F <file>`; and clearing by assignment
  (`$env:NAME = $null`). Removing one is quiet: `Remove-Item Env:NAME` (or
  `unset NAME`) for this session, `Remove-ItemProperty -Path
  HKCU:\Environment -Name NAME` (or `reg delete HKCU\Environment /v NAME /f`)
  for a saved one; the block message says the same. Twelve `[1.6.1]` probes
  in `verify-floor.sh` (nine block, three stay quiet); the plugin battery now
  fails a release whose version is not a probe tag, and every block site's
  reason is checked to parse as JSON. Battery: 322 cases (was 232); every new
  BLOCK case is a planted failure against 1.6.0.
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

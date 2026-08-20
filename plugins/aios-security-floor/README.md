# TrueNorth AIOS Security Floor

Two hooks, one job: a hard floor under every permission mode.

## What it carries

1. **`hooks/security-guard.sh`** - PreToolUse guard. Blocks credential/secret reads
   and catastrophic, irreversible commands. Runs in EVERY permission mode, including
   bypass. Deliberately quiet: normal work never triggers it. When it blocks, it
   explains why in plain language.
2. **`hooks/check-claude-code-version.mjs`** - SessionStart watcher. Nudges when the
   installed Claude Code is behind (stale installs carry security-fix gaps, not just
   feature gaps). Cached 24h, never blocks, silent on any error.

## What it deliberately does NOT do

- No discretionary command blocking (git reset, scoped deletes - recoverable, routine)
- No data collection, no network calls except the npm registry version check
- No statusline, no settings changes - those belong to the install-time layer

## For maintainers

The canonical sources live in the operator workspace at
`reference/handoff/client-security-guard.sh` and
`reference/handoff/check-claude-code-version.template.mjs`.
The copies here are BUILT by `build-floor-plugin.sh` and byte-checked by
`_test-floor-plugin.sh`. Never edit the copies in this tree directly - the battery
fails on any drift.

Release: edit canonical -> build -> run both batteries -> bump `version` in
`.claude-plugin/plugin.json` -> sync to the marketplace repo.

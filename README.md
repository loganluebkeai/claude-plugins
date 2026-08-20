# TrueNorth Plugin Marketplace

Claude Code plugins from TrueNorth Intell for AIOS client machines.

## What is in here

| Plugin | What it does |
|--------|--------------|
| `aios-security-floor` | The security floor: a guard that blocks catastrophic, irreversible actions in every permission mode - including bypass - plus a Claude Code version watcher. Your keys stay private, even from the assistant. |

## Install

```
/plugin marketplace add <this-repo>
/plugin install aios-security-floor@truenorth
```

On managed AIOS installs this is pre-wired during setup - you never need to run these.

## The design rule behind the floor

Block only what is catastrophic AND irreversible. Everything else passes silently.
A gate that fires during normal work gets worked around; a gate that never fires
is still there when it matters. In normal use this floor should never once trigger.

## Updates

Each release bumps the plugin version. Your machine picks it up on the next
marketplace refresh; nothing on your box is overwritten and nothing of yours is read.

---

Maintained by TrueNorth Intell. Source of truth for the guard lives in the operator
workspace; this repo is the published image. Do not edit files here directly.

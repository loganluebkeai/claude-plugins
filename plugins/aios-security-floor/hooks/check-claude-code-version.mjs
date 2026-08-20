#!/usr/bin/env node
// SessionStart hook -- nudges the operator to update Claude Code if behind.
// Cross-platform Node.js. Fires once per session start; cached for 24h.
// Never blocks: any error path returns silent {"continue": true}.
//
// Driver: Anthropic shipped 7+ permission-bypass / sandbox fixes across Claude
// Code 2.1.143 -> 2.1.149 (5/15-5/22). Stale installs aren't just behind on
// features -- they carry CVE-shaped bypass risk.
//
// Master template at reference/handoff/check-claude-code-version.template.mjs.
// Per-client copy at .claude/hooks/check-claude-code-version.mjs (injected by
// installer build scripts; never operator-edited inside a client workspace).

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CACHE_FILE = join(tmpdir(), 'claude-code-version-check.json');
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 2000;
const NPM_REGISTRY_URL = 'https://registry.npmjs.org/@anthropic-ai/claude-code/latest';

function emit(additionalContext) {
  const out = { continue: true };
  if (additionalContext) {
    out.hookSpecificOutput = { hookEventName: 'SessionStart', additionalContext };
  }
  process.stdout.write(JSON.stringify(out));
}

function getInstalledVersion() {
  // execFileSync (no shell) -- safe even though args are hard-coded.
  try {
    const out = execFileSync('claude', ['--version'], {
      encoding: 'utf8',
      timeout: 3000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const match = out.match(/(\d+\.\d+\.\d+)/);
    return match ? match[1] : null;
  } catch { return null; }
}

async function getLatestVersion() {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(NPM_REGISTRY_URL, { signal: controller.signal });
    if (!response.ok) return null;
    const data = await response.json();
    return typeof data.version === 'string' ? data.version : null;
  } catch { return null; }
  finally { clearTimeout(timeoutId); }
}

function readCache() {
  if (!existsSync(CACHE_FILE)) return null;
  try { return JSON.parse(readFileSync(CACHE_FILE, 'utf8')); } catch { return null; }
}

function writeCache(payload) {
  try { writeFileSync(CACHE_FILE, JSON.stringify(payload)); } catch {}
}

function compareVersions(a, b) {
  const pa = a.split('.').map((n) => Number.parseInt(n, 10));
  const pb = b.split('.').map((n) => Number.parseInt(n, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const ai = pa[i] ?? 0, bi = pb[i] ?? 0;
    if (ai !== bi) return ai < bi ? -1 : 1;
  }
  return 0;
}

function buildNudge(installed, latest) {
  return `Claude Code is behind: installed ${installed}, latest ${latest}. Suggest running /claude-update at a clean break in the conversation. Don't block the current task.`;
}

async function main() {
  const installed = getInstalledVersion();
  if (!installed) return emit(null);
  const now = Date.now();
  const cached = readCache();
  if (cached && now - cached.timestamp < CACHE_TTL_MS && typeof cached.latest === 'string') {
    if (compareVersions(installed, cached.latest) < 0) return emit(buildNudge(installed, cached.latest));
    return emit(null);
  }
  const latest = await getLatestVersion();
  if (!latest) return emit(null);
  writeCache({ timestamp: now, latest, installed });
  if (compareVersions(installed, latest) < 0) return emit(buildNudge(installed, latest));
  return emit(null);
}

main().catch(() => emit(null));

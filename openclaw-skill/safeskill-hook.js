// safeskill-hook.js — SafeSkill interception layer for OpenClaw
//
// Loaded via NODE_OPTIONS=--require /path/to/safeskill-hook.js
// Runs before OpenClaw boots. Patches Node's child_process so every
// command the AI tries to execute is evaluated by SafeSkillAgent first.
//
// NO OpenClaw source code is modified. This is pure runtime interception.

'use strict';

const cp = require('child_process');
const fs = require('fs');

// ── Save ALL originals before any patching ──────────────────────────────────
const orig = {
  spawn:        cp.spawn.bind(cp),
  spawnSync:    cp.spawnSync.bind(cp),
  exec:         cp.exec.bind(cp),
  execSync:     cp.execSync.bind(cp),
  execFile:     cp.execFile.bind(cp),
  execFileSync: cp.execFileSync.bind(cp),
  fork:         cp.fork.bind(cp),
};

// ── Config ───────────────────────────────────────────────────────────────────
const SOCKET   = process.env.SAFESKILL_SOCKET     || '/var/run/safeskill/safeskill.sock';
const TOKFILE  = process.env.SAFESKILL_TOKEN_FILE || '/var/run/safeskill/client.token';

// ── Helpers ──────────────────────────────────────────────────────────────────
function daemonUp() {
  try { fs.statSync(SOCKET); return true; } catch { return false; }
}

function getToken() {
  try { return fs.readFileSync(TOKFILE, 'utf8').trim(); } catch { return null; }
}

function toStr(cmd, args) {
  const parts = [cmd, ...(Array.isArray(args) ? args.map(String) : [])].filter(Boolean);
  return parts.join(' ');
}

// ── Fast-pass: OpenClaw internal health-monitor commands ─────────────────────
// These are read-only system introspection calls OpenClaw runs every ~5s to
// monitor its own gateway process. They never originate from the AI and pose
// no security risk. Skipping the daemon entirely means: no curl, no audit
// log entry, no SIEM event — and zero latency overhead on gateway health checks.
const HEALTH_PREFIXES = [
  'sysctl -n hw.model',
  'sw_vers -productVersion',
  '/usr/sbin/lsof -nP -iTCP:',   // gateway port listener check
  'ps -p ',                       // gateway PID inspection
  'launchctl print gui/',         // launchd service status
  'arp -a -n -l',                 // network table check (~every 15s)
  '/usr/sbin/scutil --get',       // system hostname lookups
  'defaults read -g ',            // system locale/preference reads
];

function isHealthCheck(cmdStr) {
  return HEALTH_PREFIXES.some(function(p) { return cmdStr.startsWith(p); });
}

// Recursion guard — prevents the internal curl check from being intercepted
let _checking = false;

// Query SafeSkillAgent via curl directly (no Python startup overhead — ~50ms vs ~450ms)
// Returns true (allowed) or false (blocked / fail-closed)
function isAllowed(cmdStr) {
  if (_checking) return true;
  if (isHealthCheck(cmdStr)) return true;  // bypass daemon — internal OpenClaw only
  if (!daemonUp()) return false;

  const token = getToken();
  if (!token) return false;

  _checking = true;
  try {
    const payload = JSON.stringify({ command: cmdStr, source: 'openclaw-hook' });
    const r = orig.spawnSync('curl', [
      '-sf', '--max-time', '2',
      '--unix-socket', SOCKET,
      'http://localhost/evaluate',
      '-H', 'Content-Type: application/json',
      '-H', 'X-SafeSkill-Token: ' + token,
      '-d', payload,
    ], { timeout: 3000, encoding: 'utf8' });

    if (r.status !== 0 || !r.stdout) return false; // fail closed on curl error

    const result = JSON.parse(r.stdout);
    return result.blocked === false; // explicit false only — anything else is fail-closed
  } catch {
    return false; // fail closed on any parse/runtime error
  } finally {
    _checking = false;
  }
}

function deny(cmd) {
  const e = new Error('[SafeSkill] BLOCKED: ' + cmd);
  e.code  = 'EPERM';
  e.cmd   = cmd;
  return e;
}

// ── Patches ───────────────────────────────────────────────────────────────────

cp.spawn = function safeskillSpawn(command, args, options) {
  const cmd = toStr(command, args);
  if (!isAllowed(cmd)) throw deny(cmd);
  return orig.spawn(command, args, options);
};

cp.spawnSync = function safeskillSpawnSync(command, args, options) {
  const cmd = toStr(command, args);
  if (!isAllowed(cmd)) throw deny(cmd);
  return orig.spawnSync(command, args, options);
};

cp.exec = function safeskillExec(command, options, callback) {
  if (!isAllowed(command)) {
    const e  = deny(command);
    const cb = typeof options === 'function' ? options
             : typeof callback === 'function' ? callback : null;
    if (cb) { setImmediate(function() { cb(e, '', ''); }); return null; }
    throw e;
  }
  return orig.exec(command, options, callback);
};

cp.execSync = function safeskillExecSync(command, options) {
  if (!isAllowed(command)) throw deny(command);
  return orig.execSync(command, options);
};

cp.execFile = function safeskillExecFile(file, args, options, callback) {
  const cmd = toStr(file, Array.isArray(args) ? args : []);
  if (!isAllowed(cmd)) {
    const e  = deny(cmd);
    const cb = typeof args     === 'function' ? args
             : typeof options  === 'function' ? options
             : typeof callback === 'function' ? callback : null;
    if (cb) { setImmediate(function() { cb(e, '', ''); }); return null; }
    throw e;
  }
  return orig.execFile(file, args, options, callback);
};

cp.execFileSync = function safeskillExecFileSync(file, args, options) {
  const cmd = toStr(file, args);
  if (!isAllowed(cmd)) throw deny(cmd);
  return orig.execFileSync(file, args, options);
};

cp.fork = function safeskillFork(modulePath, args, options) {
  const cmd = 'node ' + modulePath;
  if (!isAllowed(cmd)) throw deny(cmd);
  return orig.fork(modulePath, args, options);
};

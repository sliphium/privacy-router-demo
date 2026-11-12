import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_CONFIG = {
  privacyProfile: 'campus',
  demoMode: true,
  strictMode: false,
  thresholds: { local: 40, sanitize: 10 },
  ollama: { baseUrl: 'http://127.0.0.1:11434', model: 'qwen2.5:7b' },
  cloud: { baseUrl: 'https://api.openai.com/v1', model: 'gpt-4o-mini', apiKey: '' },
  allowLocalFallback: true,
  allowDegradeToCloud: false,
  semanticReview: false,
  timeoutMs: 300000,
};

export function loadConfig(configPath, env = process.env) {
  let stored = {};
  if (configPath && fs.existsSync(configPath)) {
    try {
      stored = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch {
      stored = {};
    }
  }
  return applyEnv(mergeConfig(DEFAULT_CONFIG, stored), env);
}

export function mergeConfig(base, patch) {
  const source = patch && typeof patch === 'object' ? patch : {};
  const merged = {
    privacyProfile: normalizeProfile(source.privacyProfile, base.privacyProfile),
    demoMode: boolOr(source.demoMode, base.demoMode),
    strictMode: boolOr(source.strictMode, base.strictMode),
    thresholds: {
      local: numberOr(source.thresholds?.local, base.thresholds.local),
      sanitize: numberOr(source.thresholds?.sanitize, base.thresholds.sanitize),
    },
    ollama: {
      baseUrl: stringOr(source.ollama?.baseUrl, base.ollama.baseUrl),
      model: stringOr(source.ollama?.model, base.ollama.model),
    },
    cloud: {
      baseUrl: stringOr(source.cloud?.baseUrl, base.cloud.baseUrl),
      model: stringOr(source.cloud?.model, base.cloud.model),
      apiKey: isMasked(source.cloud?.apiKey) ? base.cloud.apiKey : stringOr(source.cloud?.apiKey, base.cloud.apiKey),
    },
    allowLocalFallback: boolOr(source.allowLocalFallback, base.allowLocalFallback),
    allowDegradeToCloud: boolOr(source.allowDegradeToCloud, base.allowDegradeToCloud),
    semanticReview: boolOr(source.semanticReview, base.semanticReview),
    timeoutMs: numberOr(source.timeoutMs, base.timeoutMs),
  };
  return enforceThresholdOrder(merged);
}

function enforceThresholdOrder(config) {
  const sanitize = Math.min(99, Math.max(0, Math.round(config.thresholds.sanitize)));
  const local = Math.min(100, Math.max(1, Math.round(config.thresholds.local)));
  if (sanitize >= local) {
    config.thresholds = { sanitize: Math.max(0, local - 1), local };
  } else {
    config.thresholds = { sanitize, local };
  }
  return config;
}

export function applyEnv(config, env) {
  const next = mergeConfig(config, {});
  if (env.PRIVACY_ROUTER_PROFILE) next.privacyProfile = normalizeProfile(env.PRIVACY_ROUTER_PROFILE, next.privacyProfile);
  if (env.PRIVACY_ROUTER_DEMO !== undefined) next.demoMode = env.PRIVACY_ROUTER_DEMO !== '0';
  if (env.PRIVACY_ROUTER_STRICT !== undefined) next.strictMode = env.PRIVACY_ROUTER_STRICT === '1';
  if (env.CLOUD_BASE_URL) next.cloud.baseUrl = env.CLOUD_BASE_URL;
  if (env.CLOUD_MODEL) next.cloud.model = env.CLOUD_MODEL;
  if (env.CLOUD_API_KEY) next.cloud.apiKey = env.CLOUD_API_KEY;
  if (env.OLLAMA_BASE_URL) next.ollama.baseUrl = env.OLLAMA_BASE_URL;
  if (env.OLLAMA_MODEL) next.ollama.model = env.OLLAMA_MODEL;
  if (env.PRIVACY_TIMEOUT_MS && Number(env.PRIVACY_TIMEOUT_MS) > 0) {
    next.timeoutMs = Number(env.PRIVACY_TIMEOUT_MS);
  }
  return next;
}

export function saveConfig(configPath, current, patch) {
  const next = mergeConfig(current, patch);
  const dir = path.dirname(configPath);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(configPath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  return next;
}

export function redactConfig(config) {
  return {
    ...config,
    cloud: {
      baseUrl: config.cloud.baseUrl,
      model: config.cloud.model,
      apiKey: maskSecret(config.cloud.apiKey),
      hasApiKey: Boolean(config.cloud.apiKey),
    },
  };
}

export function maskSecret(value) {
  if (!value) return '';
  if (value.length <= 8) return '****';
  return `${value.slice(0, 3)}****${value.slice(-4)}`;
}

export function isMasked(value) {
  return typeof value === 'string' && /\*{2,}/.test(value);
}

function normalizeProfile(value, fallback) {
  if (value === 'campus' || value === 'enterprise') return value;
  if (value === 'balanced') return 'enterprise';
  return fallback === 'enterprise' ? 'enterprise' : 'campus';
}

function boolOr(value, fallback) {
  return typeof value === 'boolean' ? value : fallback;
}

function numberOr(value, fallback) {
  return Number.isFinite(Number(value)) ? Number(value) : fallback;
}

function stringOr(value, fallback) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : fallback;
}
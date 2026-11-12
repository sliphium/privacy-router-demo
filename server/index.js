import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadConfig, saveConfig, redactConfig, maskSecret } from './lib/config.js';
import { detectConversation, toPublicFindings } from './lib/detector.js';
import { sanitize, restore, summarizeMasks, splitStreamChunk, redactUnknownPlaceholders } from './lib/sanitizer.js';
import { initialDecision, applyRescan, applyAvailability, ROUTE_LABELS, normalizeThresholds } from './lib/router.js';
import { createAuditStore } from './lib/audit.js';
import { streamOllama, probeOllama, reviewWithOllama } from './lib/providers/ollama.js';
import { streamCloud, cloudConfigured } from './lib/providers/cloud.js';
import { streamMock } from './lib/providers/mock.js';
import { ProviderError } from './lib/providers/errors.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_DIR = path.join(ROOT, 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function createApp(options = {}) {
  const configPath = options.configPath || path.join(ROOT, 'config.json');
  const auditPath = options.auditPath || path.join(ROOT, 'data', 'audit.jsonl');
  const env = options.env || process.env;
  const audit = createAuditStore(auditPath);
  let config = loadConfig(configPath, env);

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);

    try {
      if (url.pathname === '/api/health' && request.method === 'GET') {
        return await handleHealth(response, config);
      }
      if (url.pathname === '/api/config' && request.method === 'GET') {
        return sendJson(response, 200, redactConfig(config));
      }
      if (url.pathname === '/api/config' && request.method === 'PUT') {
        const body = await readJson(request);
        config = saveConfig(configPath, config, body);
        return sendJson(response, 200, redactConfig(config));
      }
      if (url.pathname === '/api/audit' && request.method === 'GET') {
        const limit = Number(url.searchParams.get('limit')) || 50;
        return sendJson(response, 200, { records: audit.list(limit) });
      }
      if (url.pathname === '/api/audit/clear' && request.method === 'POST') {
        audit.clear();
        return sendJson(response, 200, { ok: true });
      }
      if (url.pathname === '/api/chat' && request.method === 'POST') {
        return await handleChat(request, response, { config, audit, auditPath });
      }
      if (url.pathname.startsWith('/api/')) {
        return sendJson(response, 404, { error: '接口不存在' });
      }
      if (request.method === 'GET' || request.method === 'HEAD') {
        return serveStatic(request, response, url);
      }
      return sendJson(response, 405, { error: '方法不支持' });
    } catch (error) {
      if (response.headersSent) {
        response.end();
        return;
      }
      const status = error instanceof HttpError ? error.status : 500;
      const message = error instanceof HttpError ? error.message : '服务内部错误';
      if (status >= 500) console.error('[privacy-router]', error instanceof Error ? error.message : String(error));
      sendJson(response, status, { error: message });
    }
  });

  return {
    server,
    audit,
    getConfig: () => config,
  };
}

async function handleHealth(response, config) {
  const availability = await resolveAvailability(config);
  const thresholds = normalizeThresholds(config.thresholds);
  sendJson(response, 200, {
    privacyProfile: config.privacyProfile,
    demoMode: config.demoMode,
    strictMode: config.strictMode,
    semanticReview: config.semanticReview,
    thresholds,
    availability,
    ollama: {
      baseUrl: config.ollama.baseUrl,
      model: config.ollama.model,
      available: availability.local,
      models: availability.models || [],
    },
    cloud: {
      baseUrl: config.cloud.baseUrl,
      model: config.cloud.model,
      configured: cloudConfigured(config),
      apiKey: maskSecret(config.cloud.apiKey),
    },
  });
}

async function resolveAvailability(config) {
  if (config.demoMode) {
    return { local: true, cloud: true, mode: 'demo', models: [] };
  }
  const probe = await probeOllama(config);
  return {
    local: probe.available,
    cloud: cloudConfigured(config),
    mode: 'live',
    models: probe.models,
  };
}

async function handleChat(request, response, ctx) {
  const body = await readJson(request);
  const messages = normalizeMessages(body.messages);
  if (messages.length === 0) {
    throw new HttpError(400, 'messages 不能为空');
  }
  const lastIndex = findLastUserIndex(messages);
  if (lastIndex === -1) {
    throw new HttpError(400, '缺少 user 消息');
  }

  const config = ctx.config;
  const nonce = crypto.randomBytes(3).toString('hex');
  const question = messages[lastIndex].content;
  const detection = detectConversation(messages);
  const thresholds = normalizeThresholds(config.thresholds);
  let decision = initialDecision({ score: detection.score, findings: detection.findings, config });

  let semantic = null;
  if (config.semanticReview && !config.demoMode && decision.route !== 'local') {
    const probe = await probeOllama(config, 800);
    if (probe.available) {
      semantic = await reviewWithOllama({ config, text: question });
      if (semantic && semantic.score >= thresholds.local) {
        decision = {
          ...decision,
          route: 'local',
          semanticUpgrade: true,
          reason: `本地语义复核得分 ${semantic.score} 达到阈值 ${thresholds.local}，升级为本地处理`,
        };
      }
    }
  }

  const availability = await resolveAvailability(config);
  decision = applyAvailability(decision, availability, config);

  let outboundMessages = messages;
  let masks = [];
  let outboundText = null;
  const describeOutbound = (list) => list
    .map((message) => `[${message.role}] ${message.content}`)
    .join('\n\n');

  if (decision.route === 'cloud-sanitized') {
    const cleanedMessages = [];
    const collectedMasks = [];

    for (const [index, message] of messages.entries()) {
      const cleaned = sanitize(message.content, detection.messages[index].findings, {
        prefix: `M${index + 1}_${nonce}_`,
      });
      cleanedMessages.push({ ...message, content: cleaned.text });
      collectedMasks.push(...cleaned.masks);
    }

    const rescan = detectConversation(cleanedMessages);
    const upgraded = applyRescan(decision, rescan.score, config);
    if (upgraded.route !== decision.route) {
      decision = applyAvailability(upgraded, availability, config);
    }
    if (decision.route === 'cloud-sanitized') {
      masks = collectedMasks;
      outboundMessages = cleanedMessages;
      outboundText = describeOutbound(cleanedMessages);
    }
  }

  if (decision.route === 'cloud' || decision.route === 'cloud-sanitized') {
    outboundText = outboundText || describeOutbound(outboundMessages);
  }

  const auditId = crypto.randomUUID();
  const startedAt = Date.now();
  prepareSse(response);

  const meta = {
    id: auditId,
    profile: config.privacyProfile,
    route: decision.route,
    routeLabel: ROUTE_LABELS[decision.route],
    reason: decision.reason,
    score: detection.score,
    context: {
      turns: messages.length,
      taintedTurns: detection.taintedTurns,
      lastScore: detection.messages[lastIndex] ? detection.messages[lastIndex].score : 0,
    },
    findings: toPublicFindings(detection.findings),
    thresholds,
    masks: summarizeMasks(masks),
    outboundText,
    demoMode: config.demoMode,
    strictMode: config.strictMode,
    degraded: Boolean(decision.degraded),
    upgraded: Boolean(decision.upgraded),
    criticalHit: Boolean(decision.criticalHit),
    semanticUpgrade: Boolean(decision.semanticUpgrade),
    semantic,
    availability: { local: availability.local, cloud: availability.cloud, mode: availability.mode },
    provider: decision.route === 'local' ? 'ollama' : 'cloud',
    model: decision.route === 'local' ? config.ollama.model : config.cloud.model,
  };
  sendEvent(response, 'meta', meta);

  if (decision.route === 'blocked') {
    sendEvent(response, 'error', { message: decision.reason });
    sendEvent(response, 'done', { auditId, durationMs: Date.now() - startedAt, ok: false });
    await recordAudit(ctx.audit, meta, { ok: false, error: decision.reason, durationMs: Date.now() - startedAt });
    response.end();
    return;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1000, config.timeoutMs));
  const onClose = () => {
    if (!response.writableEnded) controller.abort();
  };
  response.on('close', onClose);

  let fullText = '';
  let ok = true;
  let failure = null;
  let unresolved = 0;

  try {
    const stream = createStream({
      route: decision.route,
      config,
      messages: outboundMessages,
      question: outboundMessages[lastIndex].content,
      masks,
      score: detection.score,
      signal: controller.signal,
    });
    let pending = '';
    for await (const chunk of stream) {
      fullText += chunk;
      const split = splitStreamChunk(pending + chunk);
      pending = split.pending;
      if (split.safe) sendEvent(response, 'delta', { text: split.safe });
    }
    if (pending) sendEvent(response, 'delta', { text: pending });
    const restoredText = restore(fullText, masks);
    const final = redactUnknownPlaceholders(restoredText, masks);
    unresolved = final.count;
    sendEvent(response, 'final', {
      text: final.text,
      restored: masks.length > 0,
      unresolved: final.count,
    });
  } catch (error) {
    ok = false;
    failure = describeError(error, controller.signal);
    sendEvent(response, 'error', { message: failure });
  } finally {
    clearTimeout(timer);
    response.off('close', onClose);
  }

  const durationMs = Date.now() - startedAt;
  await recordAudit(ctx.audit, meta, { ok, error: failure, durationMs, unresolved });
  sendEvent(response, 'done', { auditId, durationMs, ok, unresolved });
  response.end();
}

function createStream({ route, config, messages, question, masks, score, signal }) {
  if (config.demoMode) {
    return streamMock({ route, config, question, masks, score, signal });
  }
  if (route === 'local') {
    return streamOllama({ config, messages: withLocalPrivacyGuard(messages), signal });
  }
  return streamCloud({ config, messages, signal });
}

function withLocalPrivacyGuard(messages) {
  return [
    {
      role: 'system',
      content: '你运行在用户本机，回答仅用于本地决策。不要复述输入中的姓名、学号、联系方式、住址、成绩、健康或心理细节；需要指代个人时使用“该同学”“相关人员”等中性表述，不要对学生做标签化判断。',
    },
    ...messages,
  ];
}

function describeError(error, signal) {
  if (signal.aborted) return '上游响应超时或连接已中断';
  if (error instanceof ProviderError) return error.message;
  return `上游调用失败：${error.message}`;
}

async function recordAudit(audit, meta, outcome) {
  const outbound = typeof meta.outboundText === 'string' ? meta.outboundText : '';
  const outboundHash = outbound
    ? crypto.createHash('sha256').update(outbound, 'utf8').digest('hex').slice(0, 24)
    : null;

  await audit.append({
    id: meta.id,
    ts: new Date().toISOString(),
    profile: meta.profile,
    route: meta.route,
    routeLabel: meta.routeLabel,
    reason: meta.reason,
    score: meta.score,
    context: meta.context,
    criticalHit: Boolean(meta.criticalHit),
    findings: meta.findings.map(({ label, weight, count, preview, redacted, tier }) => (
      redacted
        ? { label, weight, count: 0, preview: '（细节已隐去）', redacted: true, tier: 'critical' }
        : { label, weight, count, tier }
    )),
    masks: meta.masks,
    outboundHash,
    outboundLength: outbound.length,
    outboundStored: false,
    unresolvedPlaceholders: outcome.unresolved || 0,
    provider: meta.provider,
    model: meta.model,
    demoMode: meta.demoMode,
    durationMs: outcome.durationMs,
    ok: outcome.ok,
    error: outcome.ok ? null : '上游调用失败，详情仅在当次会话展示',
  });
}

function normalizeMessages(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((message) => message && typeof message.content === 'string')
    .filter((message) => ['system', 'user', 'assistant'].includes(message.role))
    .slice(-12)
    .map((message) => ({
      role: message.role,
      content: message.content.slice(0, 12000),
    }));
}

function findLastUserIndex(messages) {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i].role === 'user') return i;
  }
  return -1;
}

function prepareSse(response) {
  response.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });
}

function sendEvent(response, event, data) {
  response.write(`event: ${event}\n`);
  response.write(`data: ${JSON.stringify(data)}\n\n`);
}

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  response.end(body);
}

function serveStatic(request, response, url) {
  const pathname = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
  const resolved = path.resolve(PUBLIC_DIR, `.${pathname}`);
  if (!resolved.startsWith(`${PUBLIC_DIR}${path.sep}`) && resolved !== PUBLIC_DIR) {
    return sendJson(response, 403, { error: '禁止访问' });
  }
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    return sendJson(response, 404, { error: '页面不存在' });
  }
  const type = MIME_TYPES[path.extname(resolved)] || 'application/octet-stream';
  const body = fs.readFileSync(resolved);
  response.writeHead(200, {
    'content-type': type,
    'content-length': body.length,
    'cache-control': 'no-cache',
    'x-content-type-options': 'nosniff',
  });
  if (request.method === 'HEAD') {
    response.end();
    return;
  }
  response.end(body);
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    const limit = 1024 * 1024;
    const chunks = [];
    let size = 0;
    let settled = false;

    request.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > limit) {
        settled = true;
        reject(new HttpError(413, '请求体超过 1 MB'));
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new HttpError(400, '请求体不是合法 JSON'));
      }
    });
    request.on('error', (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}

const isEntry = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntry) {
  const app = createApp();
  const port = Number(process.env.PORT) || 7860;
  const host = process.env.HOST || '127.0.0.1';
  app.server.listen(port, host, () => {
    const config = app.getConfig();
    console.log('');
    console.log('  PrivacyRouter · 端云协同 AI 数据隐私守卫者');
    console.log(`  地址   http://${host}:${port}`);
    console.log(`  模式   ${config.demoMode ? '演示模式（Mock 应答）' : '真实调用'}`);
    console.log(`  本地   ${config.ollama.baseUrl} / ${config.ollama.model}`);
    console.log(`  云端   ${config.cloud.baseUrl} / ${config.cloud.model}`);
    console.log('');
  });
}
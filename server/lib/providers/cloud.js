import { ProviderError } from './errors.js';

const COMPLETION_PATH = /\/chat\/completions$/;
const VERSION_PATH = /\/v\d+[a-z0-9.]*$/;

export function resolveCloudEndpoint(baseUrl) {
  const raw = String(baseUrl || '').trim();
  if (!raw) return null;

  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;

  let pathname = url.pathname.replace(/\/+$/, '');
  if (COMPLETION_PATH.test(pathname)) {
    // 用户已填完整端点，原样使用
  } else if (VERSION_PATH.test(pathname)) {
    pathname = `${pathname}/chat/completions`;
  } else if (!pathname || pathname === '/') {
    pathname = '/v1/chat/completions';
  } else {
    pathname = `${pathname}/v1/chat/completions`;
  }

  url.pathname = pathname;
  url.search = '';
  url.hash = '';
  return url.toString();
}

export function inspectCloudConfig(config) {
  const cloud = config?.cloud || {};
  const apiKey = String(cloud.apiKey || '').trim();
  const model = String(cloud.model || '').trim();
  const endpoint = resolveCloudEndpoint(cloud.baseUrl);

  if (!endpoint) {
    return {
      configured: false,
      valid: false,
      endpoint: null,
      model,
      reason: '云端 baseUrl 不是合法的 http(s) 地址',
    };
  }
  if (!apiKey) {
    return { configured: false, valid: false, endpoint, model, reason: '未配置云端 API Key' };
  }
  if (!model) {
    return { configured: true, valid: false, endpoint, model, reason: '未配置云端模型名' };
  }
  return { configured: true, valid: true, endpoint, model, reason: '' };
}

export async function* streamCloud({ config, messages, signal }) {
  const info = inspectCloudConfig(config);
  if (!info.configured) {
    throw new ProviderError(`云端不可用：${info.reason}`, 'cloud', 401);
  }
  if (!info.valid) {
    throw new ProviderError(`云端配置无效：${info.reason}`, 'cloud', 400);
  }

  let response;
  try {
    response = await fetch(info.endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${config.cloud.apiKey}`,
      },
      body: JSON.stringify({
        model: config.cloud.model,
        messages,
        stream: true,
        temperature: 0.4,
      }),
      signal,
    });
  } catch (error) {
    throw new ProviderError(`无法连接云端 API：${error.message}`, 'cloud');
  }

  if (!response.ok || !response.body) {
    const detail = await safeText(response);
    throw new ProviderError(describeCloudStatus(response.status, detail), 'cloud', response.status);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || !trimmed.startsWith('data:')) continue;
      const data = trimmed.slice(5).trim();
      if (!data || data === '[DONE]') continue;
      let payload;
      try {
        payload = JSON.parse(data);
      } catch {
        continue;
      }
      const chunk = payload.choices?.[0]?.delta?.content;
      if (chunk) yield chunk;
    }
  }
}

export function describeCloudStatus(status, detail = '') {
  const suffix = detail ? `：${detail}` : '';
  if (status === 401 || status === 403) {
    return `云端鉴权失败（${status}）：请检查 API Key 是否有效、是否与 baseUrl 匹配${suffix}`;
  }
  if (status === 404) {
    return `云端接口或模型不存在（404）：请确认 baseUrl 指向 OpenAI 兼容接口（通常以 /v1 结尾），并检查模型名${suffix}`;
  }
  if (status === 429) {
    return `云端限流或余额不足（429）${suffix}`;
  }
  return `云端返回 ${status}${suffix}`;
}

export function cloudConfigured(config) {
  return inspectCloudConfig(config).valid;
}

async function safeText(response) {
  try {
    const text = await response.text();
    return text.slice(0, 200);
  } catch {
    return '';
  }
}
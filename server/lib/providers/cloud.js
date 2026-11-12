import { ProviderError } from './errors.js';

function endpoint(baseUrl, suffix) {
  const base = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  return new URL(suffix, base).toString();
}

export async function* streamCloud({ config, messages, signal }) {
  if (!config.cloud.apiKey) {
    throw new ProviderError('未配置云端 API Key，无法直连云端', 'cloud', 401);
  }

  let response;
  try {
    response = await fetch(endpoint(config.cloud.baseUrl, 'chat/completions'), {
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
    throw new ProviderError(`云端返回 ${response.status}${detail ? `：${detail}` : ''}`, 'cloud', response.status);
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

async function safeText(response) {
  try {
    const text = await response.text();
    return text.slice(0, 200);
  } catch {
    return '';
  }
}

export function cloudConfigured(config) {
  return Boolean(config.cloud.apiKey && config.cloud.baseUrl);
}
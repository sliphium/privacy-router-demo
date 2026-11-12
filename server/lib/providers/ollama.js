import { ProviderError } from './errors.js';

function endpoint(baseUrl, suffix) {
  const base = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  return new URL(suffix, base).toString();
}

export async function* streamOllama({ config, messages, signal }) {
  let response;
  try {
    response = await fetch(endpoint(config.ollama.baseUrl, 'api/chat'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: config.ollama.model,
        messages,
        stream: true,
        options: { temperature: 0.3 },
      }),
      signal,
    });
  } catch (error) {
    throw new ProviderError(`无法连接本地 Ollama：${error.message}`, 'ollama');
  }

  if (!response.ok || !response.body) {
    throw new ProviderError(`Ollama 返回 ${response.status}`, 'ollama', response.status);
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
      if (!trimmed) continue;
      let payload;
      try {
        payload = JSON.parse(trimmed);
      } catch {
        continue;
      }
      if (payload.error) {
        throw new ProviderError(String(payload.error), 'ollama', 502);
      }
      const chunk = payload.message?.content;
      if (chunk) yield chunk;
    }
  }

  const tail = buffer.trim();
  if (tail) {
    try {
      const payload = JSON.parse(tail);
      if (payload.message?.content) yield payload.message.content;
    } catch {
      return;
    }
  }
}

export async function probeOllama(config, timeoutMs = 1200) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpoint(config.ollama.baseUrl, 'api/tags'), {
      signal: controller.signal,
    });
    if (!response.ok) return { available: false, models: [] };
    const payload = await response.json();
    const models = Array.isArray(payload.models) ? payload.models.map((model) => model.name) : [];
    return { available: true, models };
  } catch {
    return { available: false, models: [] };
  } finally {
    clearTimeout(timer);
  }
}

export async function reviewWithOllama({ config, text, timeoutMs = 8000 }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpoint(config.ollama.baseUrl, 'api/chat'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: config.ollama.model,
        stream: false,
        options: { temperature: 0 },
        messages: [
          {
            role: 'system',
            content: '你是数据安全分级器。仅输出 JSON：{"score":0-100,"reason":"中文一句话"}。score 表示文本包含商业秘密、个人隐私、内部代码或未公开经营数据的风险。',
          },
          { role: 'user', content: text.slice(0, 2000) },
        ],
      }),
      signal: controller.signal,
    });
    if (!response.ok) return null;
    const payload = await response.json();
    const content = payload.message?.content || '';
    const match = content.match(/\{[\s\S]*\}/);
    if (!match) return null;
    const parsed = JSON.parse(match[0]);
    const score = Number(parsed.score);
    if (!Number.isFinite(score)) return null;
    return { score: Math.max(0, Math.min(100, Math.round(score))), reason: String(parsed.reason || '') };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
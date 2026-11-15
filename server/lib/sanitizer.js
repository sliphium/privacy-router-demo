const TOKEN_LABELS = {
  PHONE: '手机号',
  EMAIL: '邮箱',
  IDCARD: '身份证',
  BANKCARD: '银行卡',
  STUDENTID: '学号',
  NAME: '姓名',
  IP: '内网地址',
  KEY: '密钥',
  DSN: '数据库连接',
  PRIVATEKEY: '私钥',
  TOKEN: '令牌',
  PASSWORD: '口令',
  DORM: '宿舍',
  DOMAIN: '内网域名',
};

const PLACEHOLDER_WORDS = Object.values(TOKEN_LABELS).join('|');
const UNKNOWN_PLACEHOLDER = new RegExp(`[\\[【（(]\\s*(?:${PLACEHOLDER_WORDS})\\s*\\d+\\s*(?:#[A-Za-z0-9]+)?\\s*[\\]】）)]`, 'g');
const PENDING_PLACEHOLDER = /^[[【][\u4e00-\u9fa5\s\d#A-Za-z]{0,30}$/;

export function sanitize(text, findings, options = {}) {
  const source = typeof text === 'string' ? text : '';
  const counters = options.counters instanceof Map ? options.counters : new Map();
  const marker = typeof options.marker === 'string' ? options.marker : '';
  const spans = [];

  for (const finding of findings) {
    if (!finding.maskable || !finding.token) continue;
    for (const match of finding.matches) {
      spans.push({
        start: match.index,
        end: match.index + match.length,
        value: match.value,
        token: finding.token,
      });
    }
  }

  spans.sort((a, b) => a.start - b.start || b.end - a.end);

  const selected = [];
  let cursor = 0;
  for (const span of spans) {
    if (span.start < cursor) continue;
    selected.push(span);
    cursor = span.end;
  }

  const masks = [];
  let out = '';
  let position = 0;

  for (const span of selected) {
    const label = TOKEN_LABELS[span.token] || span.token;
    const index = (counters.get(span.token) || 0) + 1;
    counters.set(span.token, index);
    const placeholder = marker ? `[${label}${index}#${marker}]` : `[${label}${index}]`;
    masks.push({ placeholder, value: span.value, token: span.token });
    out += source.slice(position, span.start);
    out += placeholder;
    position = span.end;
  }

  out += source.slice(position);
  return { text: out, masks };
}

export function restore(text, masks) {
  if (!Array.isArray(masks) || masks.length === 0 || typeof text !== 'string') return text;

  let out = text;
  for (const mask of masks) {
    out = out.split(mask.placeholder).join(mask.value);
  }

  for (const mask of masks) {
    const token = mask.placeholder.slice(1, -1);
    const matched = token.match(/^(.*?)(\d+)(?:#([A-Za-z0-9]+))?$/);
    if (!matched) continue;

    const [, label, index, marker] = matched;
    const markerPart = marker ? `\\s*#\\s*${escapeRegExp(marker)}` : '';
    const pattern = `${escapeRegExp(label)}\\s*${index}${markerPart}`;
    const loose = new RegExp(`(^|[^A-Za-z0-9_])[\\[【（(]?(\\s*)${pattern}(\\s*)[\\]】）)]?(?![0-9])`, 'gi');
    out = out.replace(loose, (full, prefix, lead, tail) => `${prefix}${lead}${mask.value}${tail}`);
  }

  return out;
}

export function redactUnknownPlaceholders(text, masks) {
  const source = typeof text === 'string' ? text : '';
  if (!source) return { text: source, count: 0 };

  const known = new Set((masks || []).map((mask) => mask.placeholder));
  let count = 0;
  const out = source.replace(UNKNOWN_PLACEHOLDER, (match) => {
    if (known.has(match)) return match;
    count += 1;
    return '［未识别占位符］';
  });
  return { text: out, count };
}

export function splitStreamChunk(text) {
  const source = typeof text === 'string' ? text : '';
  const lastOpen = Math.max(source.lastIndexOf('['), source.lastIndexOf('【'));
  if (lastOpen === -1) return { safe: source, pending: '' };

  const tail = source.slice(lastOpen);
  if (!PENDING_PLACEHOLDER.test(tail)) return { safe: source, pending: '' };

  return { safe: source.slice(0, lastOpen), pending: tail };
}

export function summarizeMasks(masks) {
  if (!Array.isArray(masks)) return [];
  return masks.map(({ placeholder, token }) => ({ placeholder, token }));
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
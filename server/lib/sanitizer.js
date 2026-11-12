export function sanitize(text, findings, options = {}) {
  const source = typeof text === 'string' ? text : '';
  const prefix = options.prefix || '';
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

  const counters = new Map();
  const masks = [];
  let out = '';
  let position = 0;

  for (const span of selected) {
    const index = (counters.get(span.token) || 0) + 1;
    counters.set(span.token, index);
    const placeholder = `<PR_${prefix}${span.token}_${index}>`;
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
    const pattern = token.split('_').map(escapeRegExp).join('[\\s_-]*');
    const loose = new RegExp(`(^|[^A-Za-z0-9_])(?:<\\s*)?${pattern}(?:\\s*>)?(?![0-9])`, 'gi');
    out = out.replace(loose, (match, prefix) => `${prefix}${mask.value}`);
  }

  return out;
}

const PENDING_PLACEHOLDER = /^<[A-Za-z0-9_]{0,39}$/;

export function splitStreamChunk(text) {
  const source = typeof text === 'string' ? text : '';
  const lastOpen = source.lastIndexOf('<');
  if (lastOpen === -1) return { safe: source, pending: '' };

  const tail = source.slice(lastOpen);
  if (!PENDING_PLACEHOLDER.test(tail)) return { safe: source, pending: '' };

  return { safe: source.slice(0, lastOpen), pending: tail };
}

export function redactUnknownPlaceholders(text, masks) {
  const source = typeof text === 'string' ? text : '';
  if (!source) return { text: source, count: 0 };

  const known = new Set((masks || []).map((mask) => mask.placeholder));
  let count = 0;
  const out = source.replace(/<PR_[A-Za-z0-9_]{1,60}>/g, (match) => {
    if (known.has(match)) return match;
    count += 1;
    return '［未识别占位符］';
  });
  return { text: out, count };
}

export function summarizeMasks(masks) {
  if (!Array.isArray(masks)) return [];
  return masks.map(({ placeholder, token }) => ({ placeholder, token }));
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
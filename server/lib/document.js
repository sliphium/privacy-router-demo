import mammoth from 'mammoth';
import { PDFParse } from 'pdf-parse';
import JSZip from 'jszip';

import { detectSensitive } from './detector.js';
import { sanitize } from './sanitizer.js';

const MAX_TEXT_CHARS = 200000;

export async function extractDocumentText(buffer, filename) {
  if (/\.docx$/i.test(filename)) {
    const result = await mammoth.extractRawText({ buffer });
    const body = String(result.value || '');
    let extra = '';

    try {
      extra = await extractDocxExtraParts(buffer);
    } catch {
      extra = '';
    }

    const combined = `${body}${extra ? `\n${extra}` : ''}`;
    if (combined.length > MAX_TEXT_CHARS) {
      throw new Error(`文档超过 ${MAX_TEXT_CHARS} 字符，请拆分后扫描`);
    }
    return combined;
  }

  if (/\.pdf$/i.test(filename)) {
    const parser = new PDFParse({ data: buffer });
    try {
      const result = await parser.getText();
      const cleaned = String(result.text || '').replace(/\n?-- \d+ of \d+ --\n?/g, '\n');
      if (cleaned.length > MAX_TEXT_CHARS) {
        throw new Error(`文档超过 ${MAX_TEXT_CHARS} 字符，请拆分后扫描`);
      }
      return cleaned;
    } finally {
      if (typeof parser.destroy === 'function') await parser.destroy();
    }
  }

  throw new Error('仅支持 docx / pdf 文档');
}

async function extractDocxExtraParts(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const parts = [];

  for (const [name, entry] of Object.entries(zip.files)) {
    if (entry.dir) continue;
    if (!/^word\/(header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/.test(name)) continue;

    const uncompressed = entry._data?.uncompressedSize;
    if (typeof uncompressed === 'number' && uncompressed > 2 * 1024 * 1024) continue;

    const xml = await entry.async('string');
    if (xml.length > 2 * 1024 * 1024) continue;

    const texts = [];
    const re = /<w:t[^>]*>([^<]*)<\/w:t>/g;
    let match = re.exec(xml);

    while (match !== null) {
      const value = decodeXml(match[1]);
      if (value) texts.push(value);
      match = re.exec(xml);
    }

    if (texts.length > 0) {
      parts.push(`${partLabel(name)}：${texts.join(' ')}`);
    }
  }

  return parts.join('\n');
}

function partLabel(name) {
  if (name.includes('header')) return '页眉';
  if (name.includes('footer')) return '页脚';
  if (name.includes('footnotes')) return '脚注';
  if (name.includes('endnotes')) return '尾注';
  return '批注';
}

function decodeXml(value) {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

export function scanDocumentText(text, options = {}) {
  const source = typeof text === 'string' ? text : '';
  const marker = typeof options.marker === 'string' ? options.marker : '';
  const detection = detectSensitive(source);
  const cleaned = sanitize(source, detection.findings, { marker });

  const typeCounts = new Map();
  let criticalHits = 0;

  for (const finding of detection.findings) {
    typeCounts.set(finding.label, (typeCounts.get(finding.label) || 0) + 1);
    if (finding.tier === 'critical') criticalHits += 1;
  }

  const types = [...typeCounts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  return {
    summary: {
      chars: source.length,
      hits: detection.findings.length,
      criticalHits,
      maxScore: detection.score,
      types,
    },
    maskedText: cleaned.text,
    masks: cleaned.masks.length,
  };
}

export function recommendDocumentRoute(summary, profile) {
  if (summary.criticalHits > 0) {
    return { route: 'local', label: '本地处理', reason: '文档中存在高敏内容，建议整份留在本机' };
  }
  if (profile === 'campus' && summary.hits > 0) {
    return { route: 'local', label: '本地处理', reason: '校园严格策略：文档中存在敏感内容' };
  }
  if (summary.maxScore >= 60) {
    return { route: 'local', label: '本地处理', reason: `最高敏感度 ${summary.maxScore}，建议整份留在本机` };
  }
  if (summary.hits > 0) {
    return { route: 'cloud-sanitized', label: '脱敏后使用', reason: '命中低敏内容，导出文本已用占位符替换' };
  }
  return { route: 'cloud', label: '可使用云端', reason: '未在文档中发现敏感内容' };
}
import JSZip from 'jszip';

import { detectSensitive } from './detector.js';
import { sanitize } from './sanitizer.js';

const TARGET = /^word\/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/;
const RUN = /<w:t(\s[^>]*)?>([\s\S]*?)<\/w:t>/g;
const PARA = /<w:p(?:\s[^>]*)?>[\s\S]*?<\/w:p>/g;

export async function maskDocxPreservingFormat(buffer, marker) {
  const zip = await JSZip.loadAsync(buffer);
  const counters = new Map();
  const stats = { runsMasked: 0, paragraphsMerged: 0, metadataCleared: 0 };

  for (const name of Object.keys(zip.files)) {
    if (!TARGET.test(name)) continue;
    const file = zip.file(name);
    if (!file) continue;

    let xml = await file.async('string');
    xml = maskCrossRunParagraphs(xml, counters, marker, stats);
    xml = maskRuns(xml, counters, marker, stats);
    zip.file(name, xml);
  }

  await clearDocProps(zip, stats);
  await clearAppProps(zip, stats);

  const out = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
  return { buffer: out, ...stats };
}

async function clearDocProps(zip, stats) {
  const core = zip.file('docProps/core.xml');
  if (!core) return;

  const xml = await core.async('string');
  let touched = 0;
  const cleared = xml.replace(
    /<(dc:creator|cp:lastModifiedBy)([^>]*)>[\s\S]*?<\/\1>/g,
    (full, tag, attrs) => {
      const inner = full.replace(/<[^>]+>/g, '').trim();
      if (!inner) return full;
      touched += 1;
      return `<${tag}${attrs}></${tag}>`;
    },
  );

  if (touched > 0) {
    zip.file('docProps/core.xml', cleared);
    stats.metadataCleared = touched;
  }
}

async function clearAppProps(zip, stats) {
  const app = zip.file('docProps/app.xml');
  if (!app) return;

  const xml = await app.async('string');
  let touched = 0;
  const cleared = xml.replace(
    /<(Company|Manager)([^>]*)>[\s\S]*?<\/\1>/g,
    (full, tag, attrs) => {
      const inner = full.replace(/<[^>]+>/g, '').trim();
      if (!inner) return full;
      touched += 1;
      return `<${tag}${attrs}></${tag}>`;
    },
  );

  if (touched > 0) {
    zip.file('docProps/app.xml', cleared);
    stats.metadataCleared += touched;
  }
}

function maskCrossRunParagraphs(xml, counters, marker, stats) {
  return xml.replace(PARA, (paragraph) => {
    const runs = [...paragraph.matchAll(RUN)];
    if (runs.length < 2) return paragraph;

    const joined = runs.map((m) => decodeXml(m[2])).join('');
    if (!joined.trim()) return paragraph;

    const joinedMaskable = countMaskable(detectSensitive(joined).findings);
    if (joinedMaskable === 0) return paragraph;

    let singleMaskable = 0;
    for (const m of runs) {
      singleMaskable += countMaskable(detectSensitive(decodeXml(m[2])).findings);
    }
    if (singleMaskable >= joinedMaskable) return paragraph;

    const detection = detectSensitive(joined);
    const cleaned = sanitize(joined, detection.findings, { counters, marker }).text;
    if (cleaned === joined) return paragraph;

    let index = 0;
    const rebuilt = paragraph.replace(RUN, (full, attrs) => {
      index += 1;
      const open = attrs || '';
      if (index === 1) return `<w:t${open}>${encodeXml(cleaned)}</w:t>`;
      return `<w:t${open}></w:t>`;
    });

    stats.paragraphsMerged += 1;
    return rebuilt;
  });
}

function maskRuns(xml, counters, marker, stats) {
  return xml.replace(RUN, (full, attrs, raw) => {
    const text = decodeXml(raw);
    if (!text.trim()) return full;

    const detection = detectSensitive(text);
    if (detection.findings.length === 0) return full;

    const cleaned = sanitize(text, detection.findings, { counters, marker }).text;
    if (cleaned === text) return full;

    stats.runsMasked += 1;
    return `<w:t${attrs || ''}>${encodeXml(cleaned)}</w:t>`;
  });
}

function countMaskable(findings) {
  let total = 0;
  for (const finding of findings) {
    if (finding.maskable && Array.isArray(finding.matches)) total += finding.matches.length;
  }
  return total;
}

function decodeXml(value) {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function encodeXml(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
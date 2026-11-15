import XLSX from 'xlsx';

import { detectColumnCell } from './detector.js';
import { sanitize } from './sanitizer.js';

const MAX_ROWS = 2000;
const MAX_COLS = 80;
const MAX_SHEETS = 8;

export function parseWorkbook(buffer, filename) {
  const isText = /\.(csv|tsv)$/i.test(filename);
  const workbook = isText
    ? XLSX.read(buffer.toString('utf8'), { type: 'string', raw: true })
    : XLSX.read(buffer, { type: 'buffer', cellDates: false });

  const sheets = [];
  for (const name of workbook.SheetNames.slice(0, MAX_SHEETS)) {
    const sheet = workbook.Sheets[name];
    const rawRows = XLSX.utils.sheet_to_json(sheet, { header: 1, raw: false, defval: '' });
    const rows = rawRows.slice(0, MAX_ROWS).map((row) => row
      .slice(0, MAX_COLS)
      .map((cell) => String(cell ?? '')));
    sheets.push({
      name,
      rows,
      totalRows: rawRows.length,
      totalCols: rawRows.reduce((max, row) => Math.max(max, row.length), 0),
    });
  }
  return sheets;
}

export function scanWorkbook(sheets, options = {}) {
  const marker = typeof options.marker === 'string' ? options.marker : '';
  const counters = options.counters instanceof Map ? options.counters : new Map();
  const typeCounts = new Map();
  const scannedSheets = [];

  let cells = 0;
  let hits = 0;
  let criticalHits = 0;
  let maxScore = 0;

  for (const sheet of sheets) {
    const rows = [];
    const headerRow = sheet.rows[0] || [];
    for (const row of sheet.rows) {
      const maskedRow = [];
      for (const [columnIndex, cell] of row.entries()) {
        if (!cell) {
          maskedRow.push(cell);
          continue;
        }
        cells += 1;
        const detection = detectColumnCell(cell, String(headerRow[columnIndex] || ''));
        if (detection.findings.length === 0) {
          maskedRow.push(cell);
          continue;
        }

        hits += 1;
        maxScore = Math.max(maxScore, detection.score);
        if (detection.findings.some((finding) => finding.tier === 'critical')) criticalHits += 1;
        for (const finding of detection.findings) {
          typeCounts.set(finding.label, (typeCounts.get(finding.label) || 0) + 1);
        }
        maskedRow.push(sanitize(cell, detection.findings, { counters, marker }).text);
      }
      rows.push(maskedRow);
    }

    scannedSheets.push({
      name: sheet.name,
      rows,
      totalRows: sheet.totalRows,
      totalCols: sheet.totalCols,
    });
  }

  const types = [...typeCounts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  return {
    sheets: scannedSheets,
    summary: { cells, hits, criticalHits, maxScore, types },
  };
}

export function buildWorkbook(sheets) {
  const workbook = XLSX.utils.book_new();
  for (const sheet of sheets) {
    const worksheet = XLSX.utils.aoa_to_sheet(sheet.rows);
    const name = (sheet.name || 'Sheet1').slice(0, 31);
    XLSX.utils.book_append_sheet(workbook, worksheet, name);
  }
  return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
}

export function recommendRoute(summary, profile) {
  if (summary.criticalHits > 0) {
    return { route: 'local', label: '本地处理', reason: '表格中存在高敏单元格，整份文件按本地处理' };
  }
  if (profile === 'campus' && summary.hits > 0) {
    return { route: 'local', label: '本地处理', reason: '校园严格策略：表格中存在敏感单元格' };
  }
  if (summary.maxScore >= 60) {
    return { route: 'local', label: '本地处理', reason: `最高敏感度 ${summary.maxScore}，建议整份文件留在本机` };
  }
  if (summary.hits > 0) {
    return { route: 'cloud-sanitized', label: '脱敏后使用', reason: '命中低敏单元格，导出文件已用占位符替换' };
  }
  return { route: 'cloud', label: '可使用云端', reason: '未在单元格中发现敏感内容' };
}
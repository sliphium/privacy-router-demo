import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { extractImageText, closeOcrWorker } from '../server/lib/ocr.js';
import { scanDocumentText } from '../server/lib/document.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const file = process.argv[2] || path.join(root, 'test/fixtures/ocr-sample.png');

try {
  const text = await extractImageText(file);
  const scanned = scanDocumentText(text, { marker: 'ocrcheck' });
  console.log('OCR text:', text.replace(/\n/g, ' / '));
  console.log('chars:', scanned.summary.chars, 'hits:', scanned.summary.hits, 'max:', scanned.summary.maxScore);
  console.log('masked leaks phone:', scanned.maskedText.includes('13800138000'));
} finally {
  await closeOcrWorker();
}
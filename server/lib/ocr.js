import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createWorker } from 'tesseract.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const LANG_PATH = path.join(root, 'tessdata');
const OCR_TIMEOUT_MS = 60000;

let workerPromise = null;
let queue = Promise.resolve();

async function getWorker() {
  if (!workerPromise) {
    workerPromise = createWorker('chi_sim', 1, {
      langPath: LANG_PATH,
      gzip: false,
    });
  }
  return workerPromise;
}

export async function extractImageText(buffer) {
  const worker = await getWorker();

  const run = queue.then(async () => {
    let timer;
    try {
      const recognition = worker.recognize(buffer);
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('OCR 超时，请压缩图片或降低分辨率')), OCR_TIMEOUT_MS);
      });
      const { data } = await Promise.race([recognition, timeout]);
      return normalizeOcrText(data.text || '');
    } finally {
      clearTimeout(timer);
    }
  });

  queue = run.then(() => undefined, () => undefined);
  return run;
}

export async function closeOcrWorker() {
  if (!workerPromise) return;
  const worker = await workerPromise;
  await worker.terminate();
  workerPromise = null;
}

function normalizeOcrText(text) {
  return String(text)
    .replace(/([\u4e00-\u9fa5])\s+(?=[\u4e00-\u9fa5])/g, '$1')
    .replace(/\s+([，。、；：！？（）《》])/g, '$1')
    .replace(/([，。、；：！？（）《》])\s+/g, '$1')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}
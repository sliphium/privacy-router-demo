import fsp from 'node:fs/promises';
import path from 'node:path';

const MAX_READ_BYTES = 512 * 1024;

export function createAuditStore(filePath) {
  let queue = Promise.resolve();

  const ensureDir = async () => {
    if (filePath) await fsp.mkdir(path.dirname(filePath), { recursive: true });
  };

  return {
    append(entry) {
      if (!filePath) return Promise.resolve();
      const line = `${JSON.stringify(entry)}\n`;
      queue = queue
        .then(async () => {
          await ensureDir();
          await fsp.appendFile(filePath, line, 'utf8');
        })
        .catch((error) => {
          console.error('[privacy-router] 审计写入失败：', error.message);
        });
      return queue;
    },

    async list(limit = 50) {
      if (!filePath) return [];
      try {
        const stats = await fsp.stat(filePath);
        if (stats.size === 0) return [];

        const count = Math.max(1, Math.min(Number(limit) || 50, 500));
        const start = Math.max(0, stats.size - MAX_READ_BYTES);
        const length = stats.size - start;
        const handle = await fsp.open(filePath, 'r');

        try {
          const buffer = Buffer.alloc(length);
          await handle.read(buffer, 0, length, start);
          let text = buffer.toString('utf8');
          if (start > 0) {
            const newline = text.indexOf('\n');
            if (newline !== -1) text = text.slice(newline + 1);
          }

          const records = [];
          for (const line of text.split('\n').filter(Boolean).slice(-count)) {
            try {
              records.push(JSON.parse(line));
            } catch {
              continue;
            }
          }
          return records.reverse();
        } finally {
          await handle.close();
        }
      } catch {
        return [];
      }
    },

    async clear() {
      if (!filePath) return;
      queue = queue
        .then(async () => {
          await ensureDir();
          await fsp.writeFile(filePath, '', 'utf8');
        })
        .catch((error) => {
          console.error('[privacy-router] 审计清空失败：', error.message);
        });
      await queue;
    },
  };
}
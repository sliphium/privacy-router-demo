import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const MAX_READ_BYTES = 512 * 1024;

export function createAuditStore(filePath, options = {}) {
  const platform = options.platform || process.platform;
  const posixPermissions = platform !== 'win32';
  const fileMode = posixPermissions ? { mode: 0o600 } : {};
  let queue = Promise.resolve();
  let lastHash = null;
  let initialized = false;

  const permission = () => (posixPermissions
    ? { model: 'posix-mode', enforced: true, note: '文件权限已设为 0600，仅当前用户可读写' }
    : {
      model: 'ntfs-acl',
      enforced: false,
      note: 'Windows 不支持 POSIX 权限位，stat.mode 对普通文件恒为 0666；请用 NTFS ACL 限制审计文件访问',
    });

  const runExclusive = (task) => {
    const run = queue.then(task, task);
    queue = run.then(() => undefined, () => undefined);
    return run;
  };

  const ensureDir = async () => {
    if (filePath) await fsp.mkdir(path.dirname(filePath), { recursive: true });
  };

  return {
    append(entry) {
      if (!filePath) return Promise.resolve();
      return runExclusive(async () => {
        if (!initialized) {
          lastHash = await readTailHash(filePath);
          initialized = true;
          if (posixPermissions) {
            try {
              await fsp.chmod(filePath, 0o600);
            } catch {
              // 新文件由 appendFile 的 mode 控制
            }
          }
        }
        await ensureDir();
        const payload = { ...entry, prevHash: lastHash };
        const hash = hashRecord(payload, lastHash);
        await fsp.appendFile(filePath, `${JSON.stringify({ ...payload, hash })}\n`, {
          encoding: 'utf8',
          ...fileMode,
        });
        lastHash = hash;
      }).catch((error) => {
        console.error('[privacy-router] 审计写入失败：', error.message);
      });
    },

    list(limit = 50) {
      if (!filePath) return Promise.resolve([]);
      return runExclusive(() => readLatest(filePath, limit)).catch(() => []);
    },

    async clear() {
      if (!filePath) return;
      await runExclusive(async () => {
        await ensureDir();
        const clearedCount = await countRecords(filePath);
        const previousHash = lastHash || (await readTailHash(filePath));

        await fsp.writeFile(filePath, '', { encoding: 'utf8', ...fileMode });
        lastHash = null;
        initialized = true;

        const payload = {
          id: crypto.randomUUID(),
          ts: new Date().toISOString(),
          kind: 'audit-clear',
          clearedCount,
          previousHash,
          ok: true,
          prevHash: null,
        };
        const hash = hashRecord(payload, null);
        await fsp.appendFile(filePath, `${JSON.stringify({ ...payload, hash })}\n`, {
          encoding: 'utf8',
          ...fileMode,
        });
        lastHash = hash;
      }).catch((error) => {
        console.error('[privacy-router] 审计清空失败：', error.message);
      });
    },

    async verify() {
      if (!filePath) return { ok: true, count: 0, brokenAt: null, legacy: 0 };
      return runExclusive(() => verifyChain(filePath))
        .catch(() => ({ ok: false, count: 0, brokenAt: 0, legacy: 0 }));
    },

    permission,
  };
}

function hashRecord(payload, prevHash) {
  return crypto.createHash('sha256').update(`${prevHash || ''}${JSON.stringify(payload)}`).digest('hex');
}

async function readTailHash(filePath) {
  try {
    const stats = await fsp.stat(filePath);
    if (stats.size === 0) return null;

    const start = Math.max(0, stats.size - 8192);
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

      const lines = text.split('\n').filter(Boolean);
      for (let index = lines.length - 1; index >= 0; index -= 1) {
        try {
          const record = JSON.parse(lines[index]);
          if (record.hash) return record.hash;
        } catch {
          continue;
        }
      }
      return null;
    } finally {
      await handle.close();
    }
  } catch {
    return null;
  }
}

async function verifyChain(filePath) {
  let text;
  try {
    text = await fsp.readFile(filePath, 'utf8');
  } catch {
    return { ok: true, count: 0, brokenAt: null, legacy: 0 };
  }

  const records = [];
  for (const line of text.split('\n').filter(Boolean)) {
    try {
      records.push(JSON.parse(line));
    } catch {
      records.push(null);
    }
  }

  let prev = null;
  let legacy = 0;
  let seenHashed = false;

  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (!record) return { ok: false, count: records.length, brokenAt: index, legacy };
    if (!record.hash) {
      if (seenHashed) {
        return { ok: false, count: records.length, brokenAt: index, legacy, reason: '无哈希记录出现在链中间' };
      }
      legacy += 1;
      continue;
    }
    seenHashed = true;

    const { hash, ...rest } = record;
    const expected = hashRecord(rest, prev);
    if (hash !== expected || (rest.prevHash || null) !== prev) {
      return { ok: false, count: records.length, brokenAt: index, legacy };
    }
    prev = hash;
  }

  return { ok: true, count: records.length, brokenAt: null, legacy };
}

async function countRecords(filePath) {
  try {
    const text = await fsp.readFile(filePath, 'utf8');
    return text.split('\n').filter(Boolean).length;
  } catch {
    return 0;
  }
}

async function readLatest(filePath, limit) {
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
}
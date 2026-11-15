import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createAuditStore } from '../server/lib/audit.js';

function tempStore(t, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-audit-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return { store: createAuditStore(path.join(dir, 'audit.jsonl'), options), dir };
}

test('并发追加保持顺序且不丢记录', async (t) => {
  const { store, dir } = tempStore(t);
  await Promise.all(Array.from({ length: 100 }, (_, index) => store.append({ id: index })));

  const lines = fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 100);
  const ids = lines.map((line) => JSON.parse(line).id);
  assert.deepEqual(ids, Array.from({ length: 100 }, (_, index) => index));
});

test('列表按最新在前并限制条数', async (t) => {
  const { store } = tempStore(t);
  for (let index = 0; index < 5; index += 1) {
    await store.append({ id: index });
  }

  const records = await store.list(2);
  assert.deepEqual(records.map((record) => record.id), [4, 3]);
});

test('空文件与不存在的文件返回空列表', async (t) => {
  const { store, dir } = tempStore(t);
  assert.deepEqual(await store.list(), []);

  fs.writeFileSync(path.join(dir, 'audit.jsonl'), '');
  assert.deepEqual(await store.list(), []);
});

test('清空后保留 audit-clear 锚点', async (t) => {
  const { store } = tempStore(t);
  await store.append({ id: 1 });
  const before = await store.list(1);
  await store.clear();
  const records = await store.list();

  assert.equal(records.length, 1);
  assert.equal(records[0].kind, 'audit-clear');
  assert.equal(records[0].clearedCount, 1);
  assert.equal(records[0].previousHash, before[0].hash);

  const verified = await store.verify();
  assert.equal(verified.ok, true);
  assert.equal(verified.count, 1);
});

test('大文件只读取末尾且仍返回最新记录', async (t) => {
  const { store, dir } = tempStore(t);
  const file = path.join(dir, 'audit.jsonl');
  const filler = JSON.stringify({ id: 'filler', note: 'x'.repeat(200) });
  const body = Array.from({ length: 4000 }, () => filler).join('\n');
  fs.writeFileSync(file, `${body}\n${JSON.stringify({ id: 'latest' })}\n`);

  const records = await store.list(1);
  assert.equal(records.length, 1);
  assert.equal(records[0].id, 'latest');
});

test('并发读写不会读到半行或丢失记录', async (t) => {
  const { store } = tempStore(t);
  const operations = [];

  for (let index = 0; index < 50; index += 1) {
    operations.push(store.append({ id: index }));
    if (index % 5 === 0) operations.push(store.list(100));
  }
  await Promise.all(operations);

  const records = await store.list(100);
  assert.equal(records.length, 50);
  for (const record of records) {
    assert.equal(typeof record.id, 'number');
  }
});

test('审计链式哈希可校验，并能发现篡改', async (t) => {
  const { store, dir } = tempStore(t);
  await store.append({ id: 1, score: 10 });
  await store.append({ id: 2, score: 20 });

  const ok = await store.verify();
  assert.equal(ok.ok, true);
  assert.equal(ok.count, 2);
  assert.equal(ok.brokenAt, null);

  const file = path.join(dir, 'audit.jsonl');
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  const first = JSON.parse(lines[0]);
  first.score = 999;
  lines[0] = JSON.stringify(first);
  fs.writeFileSync(file, `${lines.join('\n')}\n`);

  const broken = await store.verify();
  assert.equal(broken.ok, false);
  assert.equal(broken.brokenAt, 0);
});

test('审计文件权限为 0600', { skip: process.platform === 'win32' && 'Windows 不支持 POSIX 权限位' }, async (t) => {
  const { store, dir } = tempStore(t);
  await store.append({ id: 1 });
  const stats = fs.statSync(path.join(dir, 'audit.jsonl'));
  assert.equal(stats.mode & 0o777, 0o600);
});

test('POSIX 平台明确声明 posix-mode', async (t) => {
  const { store, dir } = tempStore(t, { platform: 'linux' });
  const permission = store.permission();
  assert.equal(permission.model, 'posix-mode');
  assert.equal(permission.enforced, true);

  // 这里的 platform 只是逻辑平台；文件系统仍是当前平台，
  // Windows 上 stat.mode 恒为 0o666，无法断言 POSIX 权限位。
  if (process.platform === 'win32') return;

  await store.append({ id: 1 });
  const stats = fs.statSync(path.join(dir, 'audit.jsonl'));
  assert.equal(stats.mode & 0o777, 0o600);
});

test('Windows 声明 NTFS ACL 模型，不冒充 0600 且链仍可校验', async (t) => {
  const { store } = tempStore(t, { platform: 'win32' });
  const permission = store.permission();
  assert.equal(permission.model, 'ntfs-acl');
  assert.equal(permission.enforced, false);
  assert.match(permission.note, /NTFS ACL/);
  assert.match(permission.note, /0666/);

  await store.append({ id: 1 });
  await store.append({ id: 2 });

  const records = await store.list();
  assert.equal(records.length, 2);
  assert.equal((await store.verify()).ok, true);
});

test('链中间插入无哈希记录会被判定为断链', async (t) => {
  const { store, dir } = tempStore(t);
  await store.append({ id: 1 });
  const file = path.join(dir, 'audit.jsonl');
  fs.appendFileSync(file, `${JSON.stringify({ id: 'legacy', ts: new Date().toISOString() })}\n`);

  const broken = await store.verify();
  assert.equal(broken.ok, false);
  assert.equal(broken.brokenAt, 1);
  assert.match(broken.reason || '', /无哈希记录/);
});
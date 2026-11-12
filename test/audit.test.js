import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createAuditStore } from '../server/lib/audit.js';

function tempStore(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-audit-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return { store: createAuditStore(path.join(dir, 'audit.jsonl')), dir };
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

test('清空后列表为空', async (t) => {
  const { store } = tempStore(t);
  await store.append({ id: 1 });
  await store.clear();
  assert.deepEqual(await store.list(), []);
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
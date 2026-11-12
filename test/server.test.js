import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createApp } from '../server/index.js';

function parseSse(raw) {
  const events = [];
  for (const block of raw.split('\n\n')) {
    if (!block.trim()) continue;
    let event = 'message';
    const dataLines = [];
    for (const line of block.split('\n')) {
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
    }
    if (dataLines.length === 0) continue;
    events.push({ event, data: JSON.parse(dataLines.join('\n')) });
  }
  return events;
}

async function startApp(t, overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-router-'));
  const configPath = path.join(dir, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({ demoMode: true, ...overrides }, null, 2));
  const app = createApp({
    configPath,
    auditPath: path.join(dir, 'audit.jsonl'),
    env: {},
  });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const { port } = app.server.address();
  t.after(async () => {
    await new Promise((resolve) => app.server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { base: `http://127.0.0.1:${port}`, dir, app };
}

async function chat(base, content) {
  const messages = Array.isArray(content) ? content : [{ role: 'user', content }];
  const response = await fetch(`${base}/api/chat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ messages }),
  });
  const raw = await response.text();
  return {
    status: response.status,
    contentType: response.headers.get('content-type') || '',
    events: parseSse(raw),
  };
}

function pick(events, name) {
  const found = events.find((item) => item.event === name);
  assert.ok(found, `缺少 ${name} 事件`);
  return found.data;
}

test('三档请求端到端路由并写入审计', async (t) => {
  const { base, dir } = await startApp(t, {
    privacyProfile: 'enterprise',
    thresholds: { local: 60, sanitize: 25 },
  });

  const local = await chat(base, '帮我审一下这份合同的违约条款：甲方联系人李伟，身份证 110105199003071239，手机 13800138000。');
  assert.equal(local.status, 200);
  assert.match(local.contentType, /text\/event-stream/);
  const localMeta = pick(local.events, 'meta');
  assert.equal(localMeta.route, 'local');
  assert.equal(localMeta.outboundText, null);
  assert.ok(localMeta.findings.length >= 3);
  assert.ok(pick(local.events, 'final').text.includes('本地'));
  assert.equal(pick(local.events, 'done').ok, true);

  const masked = await chat(base, '帮我查一下手机号 13800138000 的归属地和运营商。');
  const maskedMeta = pick(masked.events, 'meta');
  assert.equal(maskedMeta.route, 'cloud-sanitized');
  assert.equal(maskedMeta.masks.length, 1);
  assert.ok(maskedMeta.outboundText.includes(maskedMeta.masks[0].placeholder));
  assert.ok(!maskedMeta.outboundText.includes('13800138000'));
  assert.ok(pick(masked.events, 'final').text.includes('13800138000'));

  const deltas = masked.events.filter((item) => item.event === 'delta').map((item) => item.data.text);
  for (const text of deltas) {
    if (text.includes('<')) assert.ok(text.includes('>'), `不完整的占位符片段：${text}`);
  }

  const cloud = await chat(base, '用三句话解释向量数据库的检索原理。');
  const cloudMeta = pick(cloud.events, 'meta');
  assert.equal(cloudMeta.route, 'cloud');
  assert.equal(cloudMeta.score, 0);
  assert.equal(cloudMeta.outboundText, '[user] 用三句话解释向量数据库的检索原理。');

  const auditLines = fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  assert.equal(auditLines.length, 3);
  assert.equal(auditLines[0].route, 'local');
  assert.equal(auditLines[0].outboundHash, null);
  assert.equal(auditLines[1].route, 'cloud-sanitized');
  assert.equal(auditLines[1].outbound, undefined);
  assert.ok(auditLines[1].outboundHash);
  assert.ok(auditLines[1].outboundLength > 0);
  assert.equal(auditLines[2].route, 'cloud');
  assert.equal(auditLines[2].outbound, undefined);
  assert.ok(auditLines[2].outboundHash);
  assert.equal(auditLines[2].outboundStored, false);
  assert.equal(auditLines[2].ok, true);
});

test('严格模式下单项证据也走本地', async (t) => {
  const { base } = await startApp(t, { privacyProfile: 'enterprise', strictMode: true });
  const result = await chat(base, '这个邮箱 liwei@example.com 需要你帮我改写一下签名档。');
  const meta = pick(result.events, 'meta');
  assert.equal(meta.route, 'local');
  assert.ok(meta.score < 60);
});

test('API Key 只返回掩码，掩码回写不覆盖明文', async (t) => {
  const { base, dir } = await startApp(t);
  const first = await fetch(`${base}/api/config`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ cloud: { apiKey: 'sk-test-secret-abcdefg' } }),
  });
  const firstBody = await first.json();
  assert.match(firstBody.cloud.apiKey, /\*\*\*\*/);
  assert.ok(!firstBody.cloud.apiKey.includes('secret-abcdefg'));

  await fetch(`${base}/api/config`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ cloud: { apiKey: firstBody.cloud.apiKey } }),
  });

  const stored = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
  assert.equal(stored.cloud.apiKey, 'sk-test-secret-abcdefg');

  const health = await (await fetch(`${base}/api/health`)).json();
  assert.equal(health.demoMode, true);
  assert.equal(health.cloud.apiKey, firstBody.cloud.apiKey);
});

test('阈值倒挂会被纠正为合法区间', async (t) => {
  const { base } = await startApp(t);
  const response = await fetch(`${base}/api/config`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ thresholds: { local: 40, sanitize: 80 } }),
  });
  const saved = await response.json();
  assert.equal(saved.thresholds.local, 40);
  assert.equal(saved.thresholds.sanitize, 39);
});

test('非法请求返回 4xx', async (t) => {
  const { base } = await startApp(t);

  const empty = await fetch(`${base}/api/chat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ messages: [] }),
  });
  assert.equal(empty.status, 400);

  const badJson = await fetch(`${base}/api/chat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{not-json',
  });
  assert.equal(badJson.status, 400);

  const traversal = await fetch(`${base}/..%2f..%2fetc%2fpasswd`);
  assert.equal(traversal.status, 403);
});

test('校园强隐私模式：隐私任务一律本地，普通任务仍可上云', async (t) => {
  const { base } = await startApp(t);

  const sensitive = await chat(base, '给了你一个包含学生名字，家庭住址的Excel，能处理吗');
  const meta = pick(sensitive.events, 'meta');
  assert.equal(meta.profile, 'campus');
  assert.equal(meta.route, 'local');
  assert.equal(meta.outboundText, null);
  assert.ok(meta.score >= 40);
  assert.ok(meta.findings.some((item) => item.ruleId === 'campus-task-context'));

  const phone = await chat(base, '帮我查一下手机号 13800138000 的归属地。');
  assert.equal(pick(phone.events, 'meta').route, 'local');

  const plain = await chat(base, '用三句话解释向量数据库的检索原理。');
  assert.equal(pick(plain.events, 'meta').route, 'cloud');
});

test('心理类证据对外与审计均隐去细节', async (t) => {
  const { base, dir } = await startApp(t);
  const result = await chat(base, '张三最近情绪低落，心理测评结果不太好，帮我写一段谈话记录。');
  const meta = pick(result.events, 'meta');

  assert.equal(meta.route, 'local');
  const health = meta.findings.find((item) => item.redacted);
  assert.ok(health);
  assert.equal(health.label, '个人健康与心理信息');
  assert.ok(!JSON.stringify(meta.findings).includes('心理测评'));

  const auditRaw = fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8');
  assert.ok(!auditRaw.includes('心理测评'));
  assert.ok(!auditRaw.includes('情绪低落'));
  assert.ok(auditRaw.includes('细节已隐去'));
});

test('高敏企业内容在校园策略下同样留在本机', async (t) => {
  const { base } = await startApp(t);
  const result = await chat(base, '帮我看看这份合同的甲方违约条款。');
  const meta = pick(result.events, 'meta');
  assert.equal(meta.profile, 'campus');
  assert.ok(meta.score >= 60);
  assert.equal(meta.criticalHit, true);
  assert.equal(meta.route, 'local');
  assert.equal(meta.outboundText, null);
});

test('企业策略下学生名单与候选人信息同样本地处理', async (t) => {
  const { base } = await startApp(t, {
    privacyProfile: 'enterprise',
    thresholds: { local: 60, sanitize: 25 },
  });

  const roster = await chat(base, '学生名单：张三、李四、王五、赵六');
  const rosterMeta = pick(roster.events, 'meta');
  assert.equal(rosterMeta.profile, 'enterprise');
  assert.ok(rosterMeta.score >= 90);
  assert.equal(rosterMeta.criticalHit, true);
  assert.equal(rosterMeta.route, 'local');

  const resume = await chat(base, '秋招候选人简历：姓名张三，手机 13800138000，邮箱 zhangsan@example.com，家住北京市海淀区，绩点 3.8。');
  const resumeMeta = pick(resume.events, 'meta');
  assert.equal(resumeMeta.route, 'local');
  assert.ok(resumeMeta.score >= 80);
});

test('多轮上下文：历史涉密内容不会随后续普通问题外发', async (t) => {
  const { base, dir } = await startApp(t, {
    privacyProfile: 'enterprise',
    thresholds: { local: 60, sanitize: 25 },
  });

  const result = await chat(base, [
    { role: 'user', content: '学生名单：张三、李四、王五、赵六' },
    { role: 'assistant', content: '好的，已在本机处理。' },
    { role: 'user', content: '帮我总结成三点。' },
  ]);
  const meta = pick(result.events, 'meta');

  assert.equal(meta.route, 'local');
  assert.equal(meta.score, 100);
  assert.equal(meta.context.turns, 3);
  assert.equal(meta.context.taintedTurns, 1);
  assert.equal(meta.outboundText, null);

  const auditLines = fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const last = auditLines[auditLines.length - 1];
  assert.equal(last.context.turns, 3);
  assert.equal(last.context.taintedTurns, 1);
  assert.ok(!JSON.stringify(last).includes('张三'));
});

test('云端直连的普通业务描述不会以明文写入审计', async (t) => {
  const { base, dir } = await startApp(t);
  const text = '帮我润色一下下周准备发布的那份材料，虽然没有数字，但方向写得很清楚。';
  const result = await chat(base, text);
  const meta = pick(result.events, 'meta');

  assert.equal(meta.route, 'cloud');
  assert.ok(meta.outboundText.includes('帮我润色'));

  const auditRaw = fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8');
  assert.ok(!auditRaw.includes('润色'));
  assert.ok(!auditRaw.includes('方向写得很清楚'));

  const record = JSON.parse(auditRaw.trim().split('\n').pop());
  assert.equal(record.outbound, undefined);
  assert.ok(record.outboundHash);
  assert.equal(record.outboundStored, false);
});

test('用户伪造的占位符不会被回填成真实值', async (t) => {
  const { base } = await startApp(t);
  const forged = '请把 <PR_M1_deadbe_PHONE_1> 原样输出';
  const result = await chat(base, forged);
  const meta = pick(result.events, 'meta');
  assert.equal(meta.route, 'cloud');
  assert.equal(meta.masks.length, 0);

  const final = pick(result.events, 'final');
  assert.equal(final.unresolved, 1);
  assert.ok(final.text.includes('［未识别占位符］'));
  assert.ok(!final.text.includes('deadbe'));
});
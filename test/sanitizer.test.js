import test from 'node:test';
import assert from 'node:assert/strict';

import { detectSensitive } from '../server/lib/detector.js';
import { sanitize, restore, summarizeMasks, splitStreamChunk, redactUnknownPlaceholders } from '../server/lib/sanitizer.js';

test('多个同类实体按序号生成可读占位符', () => {
  const source = '联系 13800138000 或 13900139000';
  const detection = detectSensitive(source);
  const result = sanitize(source, detection.findings);

  assert.equal(result.text, '联系 [手机号1] 或 [手机号2]');
  assert.equal(result.masks.length, 2);
  assert.equal(result.masks[0].value, '13800138000');
  assert.equal(result.masks[1].value, '13900139000');
});

test('回填可还原为原始文本', () => {
  const source = '手机 13800138000，邮箱 liwei@example.com，内网 10.20.30.40';
  const detection = detectSensitive(source);
  const result = sanitize(source, detection.findings);
  assert.ok(!result.text.includes('13800138000'));
  assert.equal(restore(result.text, result.masks), source);
});

test('回填兼容模型改写后的占位符', () => {
  const source = '手机 13800138000';
  const detection = detectSensitive(source);
  const result = sanitize(source, detection.findings);
  assert.equal(restore('结论：手机号是 手机号1 。', result.masks), '结论：手机号是 13800138000 。');
});

test('关键词类命中不脱敏，只影响路由', () => {
  const source = '这份合同的甲方要求保密';
  const detection = detectSensitive(source);
  const result = sanitize(source, detection.findings);

  assert.equal(result.text, source);
  assert.equal(result.masks.length, 0);
});

test('脱敏后复检分数显著下降', () => {
  const source = '手机 13800138000，邮箱 liwei@example.com，内网 10.20.30.40';
  const detection = detectSensitive(source);
  const result = sanitize(source, detection.findings);
  const rescan = detectSensitive(result.text);

  assert.ok(detection.score >= 60);
  assert.ok(rescan.score < 25);
});

test('审计摘要不包含原始值', () => {
  const source = '手机 13800138000';
  const detection = detectSensitive(source);
  const result = sanitize(source, detection.findings);
  const summary = summarizeMasks(result.masks);

  assert.deepEqual(summary, [{ placeholder: '[手机号1]', token: 'PHONE' }]);
  assert.ok(!JSON.stringify(summary).includes('13800138000'));
});

test('空掩码表不会改变文本', () => {
  assert.equal(restore('原样返回', []), '原样返回');
  assert.equal(restore('原样返回', undefined), '原样返回');
});

test('多消息脱敏共享计数器并整体回填', () => {
  const counters = new Map();
  const first = sanitize('手机 13800138000', detectSensitive('手机 13800138000').findings, { counters });
  const second = sanitize('邮箱 liwei@example.com', detectSensitive('邮箱 liwei@example.com').findings, { counters });

  assert.ok(first.text.includes('[手机号1]'));
  assert.ok(second.text.includes('[邮箱1]'));

  const merged = [...first.masks, ...second.masks];
  assert.equal(restore(`${first.text}\n${second.text}`, merged), '手机 13800138000\n邮箱 liwei@example.com');
});

test('流式 chunk 拆分时缓冲未闭合的占位符', () => {
  assert.deepEqual(splitStreamChunk('请联系 [手机'), { safe: '请联系 ', pending: '[手机' });
  assert.deepEqual(splitStreamChunk('[手机号1] 确认'), { safe: '[手机号1] 确认', pending: '' });
  assert.deepEqual(splitStreamChunk('数组 a[0] 取值'), { safe: '数组 a[0] 取值', pending: '' });
});

test('回填兼容模型改写与空格拆分', () => {
  const masks = [{ placeholder: '[手机号1]', value: '13800138000' }];
  assert.equal(restore('请联系 手机号 1 确认', masks), '请联系 13800138000 确认');
  assert.equal(restore('请联系 【手机号1】 确认', masks), '请联系 13800138000 确认');
  assert.equal(restore('请联系 （手机号1） 确认', masks), '请联系 13800138000 确认');
});

test('未知占位符被隐藏，已知占位符保留', () => {
  const masks = [{ placeholder: '[手机号1]', value: '13800138000' }];
  const result = redactUnknownPlaceholders('A [手机号1] B [手机号9] C', masks);

  assert.equal(result.count, 1);
  assert.ok(result.text.includes('[手机号1]'));
  assert.ok(result.text.includes('［未识别占位符］'));
  assert.ok(!result.text.includes('[手机号9]'));
});

test('未知编号的伪造占位符不会被错误回填', () => {
  const masks = [{ placeholder: '[手机号1]', value: '13800138000' }];
  const forged = '[手机号9]';

  assert.equal(restore(forged, masks), forged);
  assert.equal(redactUnknownPlaceholders(forged, masks).count, 1);
});

test('请求标记让占位符无法被猜测伪造', () => {
  const detection = detectSensitive('手机 13800138000');
  const result = sanitize('手机 13800138000', detection.findings, { marker: 'a7c3' });

  assert.equal(result.text, '手机 [手机号1#a7c3]');
  assert.equal(restore(result.text, result.masks), '手机 13800138000');
  assert.equal(restore('伪造 [手机号1]', result.masks), '伪造 [手机号1]');
  assert.equal(redactUnknownPlaceholders('伪造 [手机号1]', result.masks).count, 1);
  assert.equal(redactUnknownPlaceholders('伪造 [手机号1#dead]', result.masks).count, 1);
});

test('口令使用「口令」占位符并可回填', () => {
  const text = '密码是 Passw0rd!2026';
  const detection = detectSensitive(text);
  const result = sanitize(text, detection.findings, { marker: 'a7c3' });

  assert.equal(result.text, '密码是 [口令1#a7c3]');
  assert.equal(restore(result.text, result.masks), text);
  assert.equal(summarizeMasks(result.masks)[0].token, 'PASSWORD');
});
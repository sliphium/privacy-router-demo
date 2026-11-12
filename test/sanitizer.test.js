import test from 'node:test';
import assert from 'node:assert/strict';

import { detectSensitive } from '../server/lib/detector.js';
import { sanitize, restore, summarizeMasks, splitStreamChunk, redactUnknownPlaceholders } from '../server/lib/sanitizer.js';

test('多个同类实体按序号生成占位符', () => {
  const source = '联系 13800138000 或 13900139000';
  const detection = detectSensitive(source);
  const result = sanitize(source, detection.findings);

  assert.equal(result.text, '联系 <PR_PHONE_1> 或 <PR_PHONE_2>');
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
  assert.equal(restore('结论：手机号是 PR_PHONE_1 。', result.masks), '结论：手机号是 13800138000 。');
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

  assert.deepEqual(summary, [{ placeholder: '<PR_PHONE_1>', token: 'PHONE' }]);
  assert.ok(!JSON.stringify(summary).includes('13800138000'));
});

test('空掩码表不会改变文本', () => {
  assert.equal(restore('原样返回', []), '原样返回');
  assert.equal(restore('原样返回', undefined), '原样返回');
});

test('多消息脱敏使用独立前缀并可整体回填', () => {
  const first = sanitize('手机 13800138000', detectSensitive('手机 13800138000').findings, { prefix: 'M1_' });
  const second = sanitize('邮箱 liwei@example.com', detectSensitive('邮箱 liwei@example.com').findings, { prefix: 'M2_' });

  assert.ok(first.text.includes('<PR_M1_PHONE_1>'));
  assert.ok(second.text.includes('<PR_M2_EMAIL_1>'));

  const merged = [...first.masks, ...second.masks];
  assert.equal(restore(`${first.text}\n${second.text}`, merged), '手机 13800138000\n邮箱 liwei@example.com');
});

test('流式 chunk 拆分时缓冲未闭合的占位符', () => {
  assert.deepEqual(splitStreamChunk('请联系 <PHO'), { safe: '请联系 ', pending: '<PHO' });
  assert.deepEqual(splitStreamChunk('<PHONE_1> 确认'), { safe: '<PHONE_1> 确认', pending: '' });
  assert.deepEqual(splitStreamChunk('a < b'), { safe: 'a < b', pending: '' });
});

test('回填兼容模型改写与空格拆分', () => {
  const masks = [{ placeholder: '<PR_M1_PHONE_1>', value: '13800138000' }];
  assert.equal(restore('请联系 PR M1 PHONE 1 确认', masks), '请联系 13800138000 确认');
  assert.equal(restore('请联系 pr_m1_phone_1 确认', masks), '请联系 13800138000 确认');
  assert.equal(restore('请联系 < PR_M1_PHONE_1 > 确认', masks), '请联系 13800138000 确认');
});

test('未知占位符被隐藏，已知占位符保留', () => {
  const masks = [{ placeholder: '<PR_M1_ab12cd_PHONE_1>', value: '13800138000' }];
  const result = redactUnknownPlaceholders('A <PR_M1_ab12cd_PHONE_1> B <PR_fake99_M1_PHONE_9> C', masks);

  assert.equal(result.count, 1);
  assert.ok(result.text.includes('<PR_M1_ab12cd_PHONE_1>'));
  assert.ok(result.text.includes('［未识别占位符］'));
  assert.ok(!result.text.includes('fake99'));
});

test('不同 nonce 的伪造占位符不会被错误回填', () => {
  const masks = [{ placeholder: '<PR_M1_ab12cd_PHONE_1>', value: '13800138000' }];
  const forged = '<PR_M1_deadbe_PHONE_1>';

  assert.equal(restore(forged, masks), forged);
  assert.equal(redactUnknownPlaceholders(forged, masks).count, 1);
});
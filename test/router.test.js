import test from 'node:test';
import assert from 'node:assert/strict';

import {
  initialDecision,
  applyRescan,
  applyAvailability,
  normalizeThresholds,
  ROUTE_LABELS,
} from '../server/lib/router.js';

const config = {
  strictMode: false,
  thresholds: { local: 60, sanitize: 25 },
  allowLocalFallback: true,
};

const finding = { category: 'pii', weight: 58 };

test('三档阈值边界正确', () => {
  assert.equal(initialDecision({ score: 60, findings: [finding], config }).route, 'local');
  assert.equal(initialDecision({ score: 59, findings: [finding], config }).route, 'cloud-sanitized');
  assert.equal(initialDecision({ score: 25, findings: [finding], config }).route, 'cloud-sanitized');
  assert.equal(initialDecision({ score: 24, findings: [], config }).route, 'cloud');
});

test('严格模式下任意命中都走本地', () => {
  const strict = { ...config, strictMode: true };
  const decision = initialDecision({ score: 5, findings: [finding], config: strict });
  assert.equal(decision.route, 'local');
  assert.match(decision.reason, /严格模式/);
});

test('脱敏后复检达到本地阈值则升级', () => {
  const decision = { route: 'cloud-sanitized', reason: '脱敏', thresholds: config.thresholds };
  const upgraded = applyRescan(decision, 68, config);
  assert.equal(upgraded.route, 'local');
  assert.equal(upgraded.upgraded, true);

  const kept = applyRescan(decision, 10, config);
  assert.equal(kept.route, 'cloud-sanitized');
});

test('涉密任务在本地不可达时 fail-closed', () => {
  const decision = { route: 'local', reason: '涉密' };
  const blocked = applyAvailability(decision, { local: false, cloud: true }, config);
  assert.equal(blocked.route, 'blocked');
  assert.match(blocked.reason, /fail-closed/);
});

test('云端不可达时按配置决定是否本地兜底', () => {
  const decision = { route: 'cloud', reason: '直连' };
  const fallback = applyAvailability(decision, { local: true, cloud: false }, config);
  assert.equal(fallback.route, 'local');
  assert.equal(fallback.degraded, true);

  const strictFallback = applyAvailability(decision, { local: true, cloud: false }, { ...config, allowLocalFallback: false });
  assert.equal(strictFallback.route, 'blocked');

  const noLocal = applyAvailability(decision, { local: false, cloud: false }, config);
  assert.equal(noLocal.route, 'blocked');
});

test('可用性正常时保持原决策', () => {
  const decision = { route: 'cloud-sanitized', reason: '脱敏' };
  const kept = applyAvailability(decision, { local: true, cloud: true }, config);
  assert.equal(kept.route, 'cloud-sanitized');
});

test('阈值归一化处理非法值与倒挂', () => {
  assert.deepEqual(normalizeThresholds({ local: 40, sanitize: 80 }), { local: 40, sanitize: 39 });
  assert.deepEqual(normalizeThresholds(undefined), { local: 40, sanitize: 10 });
  assert.deepEqual(normalizeThresholds({ local: 'x', sanitize: 'y' }), { local: 40, sanitize: 10 });
});

test('校园强隐私模式下任意命中即本地', () => {
  const campusConfig = {
    ...config,
    privacyProfile: 'campus',
    thresholds: { local: 40, sanitize: 10 },
  };
  const decision = initialDecision({ score: 12, findings: [finding], config: campusConfig });
  assert.equal(decision.route, 'local');
  assert.equal(decision.profile, 'campus');
  assert.match(decision.reason, /校园强隐私/);

  const clean = initialDecision({ score: 0, findings: [], config: campusConfig });
  assert.equal(clean.route, 'cloud');
});

test('企业策略仍保留三档', () => {
  const enterprise = { ...config, privacyProfile: 'enterprise' };
  const decision = initialDecision({ score: 30, findings: [finding], config: enterprise });
  assert.equal(decision.route, 'cloud-sanitized');
  assert.equal(decision.profile, 'enterprise');
});

test('企业策略下高敏命中仍按最高级别本地处理', () => {
  const enterprise = {
    ...config,
    privacyProfile: 'enterprise',
    thresholds: { local: 90, sanitize: 80 },
  };
  const criticalFinding = { category: 'business', weight: 68, tier: 'critical' };
  const decision = initialDecision({ score: 68, findings: [criticalFinding], config: enterprise });
  assert.equal(decision.route, 'local');
  assert.equal(decision.criticalHit, true);
  assert.match(decision.reason, /最高敏感级别/);
});

test('旧的 balanced 配置自动归入企业策略', () => {
  const legacy = { ...config, privacyProfile: 'balanced' };
  const decision = initialDecision({ score: 30, findings: [finding], config: legacy });
  assert.equal(decision.profile, 'enterprise');
});

test('路由标签完整', () => {
  for (const route of ['local', 'cloud-sanitized', 'cloud', 'blocked']) {
    assert.equal(typeof ROUTE_LABELS[route], 'string');
  }
});
import test from 'node:test';
import assert from 'node:assert/strict';

import { detectSensitive, detectConversation, scoreFindings, toPublicFindings } from '../server/lib/detector.js';

test('普通技术问题不命中任何规则', () => {
  const result = detectSensitive('用三句话解释向量数据库的检索原理，并给一个电商场景的例子。');
  assert.equal(result.score, 0);
  assert.equal(result.findings.length, 0);
});

test('手机号命中并生成掩码预览', () => {
  const result = detectSensitive('这个手机号 13800138000 是谁的？');
  const finding = result.findings.find((item) => item.ruleId === 'phone');
  assert.ok(finding);
  assert.equal(finding.weight, 58);
  assert.equal(finding.token, 'PHONE');
  assert.equal(finding.preview, '138****8000');
  assert.equal(result.score, 58);
});

test('身份证号仅在校验位有效时命中', () => {
  const valid = detectSensitive('身份证 110105199003071239');
  assert.ok(valid.findings.some((item) => item.ruleId === 'id-card'));

  const invalid = detectSensitive('身份证 110105199003071238');
  assert.ok(!invalid.findings.some((item) => item.ruleId === 'id-card'));
});

test('云厂商密钥与数据库连接串命中', () => {
  const key = detectSensitive('请帮我检查 sk-abcdefghijklmnopqrstuvwx 这个密钥');
  assert.ok(key.findings.some((item) => item.ruleId === 'cloud-key'));
  assert.ok(key.score >= 60);

  const dsn = detectSensitive('连接串 mysql://root:Passw0rd@10.20.30.40:3306/order');
  assert.ok(dsn.findings.some((item) => item.ruleId === 'connection-string'));
});

test('内网地址命中但普通域名不命中', () => {
  const internal = detectSensitive('服务部署在 10.20.30.40 和 192.168.1.9');
  assert.ok(internal.findings.some((item) => item.ruleId === 'internal-ip'));

  const normal = detectSensitive('访问 https://example.com 查看文档');
  assert.ok(!normal.findings.some((item) => item.ruleId === 'internal-ip'));
});

test('企业业务文档同样纳管，不因策略关闭', () => {
  const legal = detectSensitive('帮我梳理这份合同的甲方违约责任条款');
  assert.ok(legal.findings.some((item) => item.ruleId === 'legal-doc'));
  assert.ok(legal.score >= 60);
  assert.ok(legal.findings.some((item) => item.tier === 'critical'));

  const secret = detectSensitive('这是未公开的商业计划，注意保密');
  assert.ok(secret.findings.some((item) => item.ruleId === 'trade-secret'));
  assert.ok(secret.score >= 60);
});

test('完整代码块被视为私有实现', () => {
  const code = '请审查这段实现：\n```js\nimport { internalClient } from "./corp-client";\nexport async function charge(orderId) {\n  return internalClient.post("/billing", { orderId });\n}\n```\n';
  const result = detectSensitive(code, { profile: 'enterprise' });
  assert.ok(result.findings.some((item) => item.ruleId === 'code-block'));
  assert.ok(result.score >= 60);
});

test('组合命中会累加并封顶 100', () => {
  const result = detectSensitive('合同甲方联系人，身份证 110105199003071239，手机 13800138000，邮箱 liwei@example.com');
  assert.equal(result.score, 100);
  assert.ok(result.findings.length >= 3);
});

test('对外结构不暴露原始命中值', () => {
  const result = detectSensitive('手机号 13800138000');
  const publicFindings = toPublicFindings(result.findings);
  assert.equal(publicFindings[0].matches, undefined);
  assert.ok(JSON.stringify(publicFindings).includes('13800138000') === false);
});

test('评分为最高权重加其余增量', () => {
  assert.equal(scoreFindings([]), 0);
  assert.equal(scoreFindings([{ weight: 60, category: 'pii' }]), 60);
  assert.equal(scoreFindings([{ weight: 60, category: 'pii' }, { weight: 40, category: 'pii' }]), 67);
});

test('校园语境任务即使没有实体也判为敏感', () => {
  const result = detectSensitive('给了你一个包含学生名字，家庭住址的Excel，能处理吗');
  assert.ok(result.findings.some((item) => item.ruleId === 'campus-task-context'));
  assert.ok(result.score >= 40);
});

test('学生名单、学号与成绩按校园规则命中', () => {
  const result = detectSensitive('学生名单：张三、李四、王五、赵六，学号 2023010101，期末成绩和绩点');
  assert.ok(result.findings.some((item) => item.ruleId === 'name-list'));
  assert.ok(result.findings.some((item) => item.ruleId === 'student-id'));
  assert.ok(result.score >= 80);
});

test('学号需上下文，普通编号不误报', () => {
  const plain = detectSensitive('订单号 2023010101 已发货');
  assert.ok(!plain.findings.some((item) => item.ruleId === 'student-id'));
});

test('心理与健康信息对外完全隐去', () => {
  const result = detectSensitive('某同学心理测评结果异常，有抑郁倾向');
  assert.ok(result.score >= 90);

  const publicFindings = toPublicFindings(result.findings);
  const health = publicFindings.find((item) => item.redacted);
  assert.ok(health);
  assert.equal(health.label, '个人健康与心理信息');

  const serialized = JSON.stringify(publicFindings);
  assert.ok(!serialized.includes('抑郁'));
  assert.ok(!serialized.includes('心理测评'));
});

test('资助、处分、党团材料命中', () => {
  const cases = [
    ['帮我核对贫困生认定和助学金名单', 'campus-aid'],
    ['这份处分决定要归档吗', 'campus-discipline'],
    ['入党积极分子谈话记录整理一下', 'campus-party'],
  ];
  for (const [text, id] of cases) {
    const result = detectSensitive(text);
    assert.ok(result.findings.some((item) => item.ruleId === id), text);
    assert.ok(result.score >= 60, text);
  }
});

test('学生个人数据不受策略影响，企业场景同样保护', () => {
  const roster = detectSensitive('学生名单：张三、李四、王五、赵六');
  const nameList = roster.findings.find((item) => item.ruleId === 'name-list');
  assert.ok(nameList);
  assert.equal(nameList.tier, 'critical');
  assert.ok(roster.score >= 90);

  const campusCommon = detectSensitive('身份证 110105199003071239');
  assert.ok(campusCommon.findings.some((item) => item.ruleId === 'id-card'));
});

test('秋招简历中的姓名、联系方式、住址与成绩被整体识别', () => {
  const resume = '秋招候选人简历：姓名张三，手机 13800138000，邮箱 zhangsan@example.com，家住北京市海淀区，绩点 3.8。';
  const result = detectSensitive(resume);
  const ids = result.findings.map((item) => item.ruleId);

  assert.ok(ids.includes('student-name'));
  assert.ok(ids.includes('phone'));
  assert.ok(ids.includes('email'));
  assert.ok(ids.includes('campus-address'));
  assert.ok(ids.includes('hr-data'));
  assert.ok(result.score >= 80);
});

test('多轮上下文整体检测：历史涉密会拖住后续普通问题', () => {
  const result = detectConversation([
    { role: 'user', content: '学生名单：张三、李四、王五、赵六' },
    { role: 'assistant', content: '好的，已在本机处理。' },
    { role: 'user', content: '帮我总结成三点。' },
  ]);

  assert.equal(result.score, 100);
  assert.equal(result.taintedTurns, 1);
  assert.equal(result.messages.length, 3);
  assert.ok(result.findings.some((item) => item.ruleId === 'name-list'));
});
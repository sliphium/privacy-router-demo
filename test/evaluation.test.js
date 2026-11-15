import test from 'node:test';
import assert from 'node:assert/strict';

import { detectSensitive } from '../server/lib/detector.js';

const NORMAL = [
  '明天下午三点在学院楼开班会，请各班班长准时参加。',
  '高数期中考试安排在周三上午，请同学们带好学生证。',
  '学生会招新面试名单已经贴在公告栏，请关注。',
  '请大家在周五前完成选课，逾期系统关闭。',
  '图书馆新增了 200 个自习座位。',
  '校园网维护通知：今晚 23:00 到次日 6:00 断网。',
  '奖学金申请材料请交到辅导员办公室。',
  '本周六组织去湖南烈士公园参观学习。',
  '请同学们填写课程评价问卷。',
  '食堂三楼新增了麻辣香锅窗口。',
  '关于举办春季运动会的通知，报名截止到 4 月 10 日。',
  '论文查重系统已开放，请在 5 月 1 日前提交。',
  '宿舍卫生检查结果将在班级群公示。',
  '请大家按时完成青年大学习。',
  '考研经验分享会定在周四晚上七点。',
  '请各班统计寒假返校时间。',
  '校园卡丢失的同学请到服务大厅补办。',
  '今天下午的讲座改到线上进行。',
  '请把课程表发到班级群。',
  '关于调整上课时间的通知。',
];

const SENSITIVE = [
  '帮我整理一下张伟、李娜、王强、刘洋的期末成绩。',
  '赵敏的身份证是 110105199003071239，手机 13800138000。',
  '这是贫困生认定名单：陈晨、周涛、吴迪。',
  '李同学最近心理测评结果不太好。',
  '入党积极分子谈话记录：王磊，2023 年 5 月。',
  '帮我统计 3 号楼 502 宿舍的晚归情况。',
  '学生名单.xlsx 里有 200 个学生的家庭住址。',
  '小美最近情绪不好，帮我写段评语。',
  'Zhang Wei 的电话是 13800138000。',
  '请把李伟的身份证照片发我。',
  '王小明同学的家长电话是 13800138000。',
];

test('固定评测集：普通校园通知误报为 0', () => {
  const flagged = NORMAL
    .map((text) => ({ text, result: detectSensitive(text) }))
    .filter((item) => item.result.score > 0);

  assert.equal(
    flagged.length,
    0,
    flagged.map((item) => `${item.result.findings.map((f) => f.ruleId).join(',')}: ${item.text}`).join('\n'),
  );
});

test('固定评测集：涉密样例漏报为 0', () => {
  const missed = SENSITIVE.filter((text) => detectSensitive(text).score === 0);
  assert.equal(missed.length, 0, missed.join('\n'));
});

test('固定评测集：分隔符拆分不能绕过', () => {
  const bypasses = [
    '帮我查 138 0013 8000 的归属地',
    '身份证 110105 19900307 1239',
    '学 生 名 单：张 三、李 四、王 五',
    '合 同 的 甲 方 违 约 条 款',
    '138\u200b0013\u200b8000',
  ];
  const missed = bypasses.filter((text) => detectSensitive(text).score === 0);
  assert.equal(missed.length, 0, missed.join('\n'));
});
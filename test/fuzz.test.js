import test from 'node:test';
import assert from 'node:assert/strict';

import { detectSensitive } from '../server/lib/detector.js';

const CASES = [
  ['phone 全角', '１３８００１３８０００'],
  ['phone 全角混合', '１38００138000'],
  ['phone 全角空格', '１３８　００１３　８０００'],
  ['phone 零宽200b', '138\u200b0013\u200b8000'],
  ['phone LRM200e', '138\u200e0013\u200e8000'],
  ['phone RLO202e', '138\u202e0013\u202e8000'],
  ['phone 软连字符', '138\u00ad0013\u00ad8000'],
  ['phone 变体选择符', '1\ufe0f3\ufe0f8\ufe0f0\ufe0f0\ufe0f1\ufe0f3\ufe0f8\ufe0f0\ufe0f0\ufe0f0\ufe0f'],
  ['phone 标签字符', '1\u{E0041}3\u{E0041}8\u{E0041}0\u{E0041}0\u{E0041}1\u{E0041}3\u{E0041}8\u{E0041}0\u{E0041}0\u{E0041}0'],
  ['phone 中文数字', '一三八零零一三八零零零'],
  ['phone URL编码', '%31%33%38%30%30%31%33%38%30%30%30'],
  ['phone HTML实体', '&#49;&#51;&#56;&#48;&#48;&#49;&#51;&#56;&#48;&#48;&#48;'],
  ['phone Base64', 'MTM4MDAxMzgwMDA='],
  ['phone 同形 l/O', 'l38OOl38OOO'],
  ['phone 组合斜杠', '1\u03383\u03388\u03380\u03380\u03381\u03383\u03388\u03380\u03380\u03380'],
  ['phone 拼音', 'yi san ba ling ling yi san ba ling ling ling'],
  ['phone 韩文填充', '138\u31640013\u31648000'],
  ['phone 盲文空白', '138\u28000013\u28008000'],
  ['phone 补充变体', '1\u{E0100}3\u{E0100}8\u{E0100}0\u{E0100}0\u{E0100}1\u{E0100}3\u{E0100}8\u{E0100}0\u{E0100}0\u{E0100}0'],
  ['keyword 全角空格', '学　生　名　单'],
  ['keyword 零宽', '学\u200b生\u200b名\u200b单'],
  ['keyword LRM', '学\u200e生\u200e名\u200e单'],
  ['keyword 中间点', '学·生·名·单'],
  ['keyword 繁体', '學生名單'],
  ['keyword 拼音', 'xueshengmingdan'],
  ['idcard 全角', '１１０１０５１９９００３０７１２３９'],
  ['idcard 中文数字', '一一零一零五一九九零零三零七一二三九'],
  ['bank 全角有效', '４１１１１１１１１１１１１１１１'],
  ['email 全角', 'ｚｈａｎｇ＠ｅｘａｍｐｌｅ．ｃｏｍ'],
  ['ip 全角', '１０．２０．３０．４０'],
  ['api key 大写', 'SK-ABCDEFGHIJKLMNOPQRSTUVWX'],
  ['api key 全角大写', 'ＳＫ－ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸ'],
  ['private key 小写', '-----begin private key-----\nMIIEowIBAAKCAQEA1234567890abcdef\n-----end private key-----'],
  ['phone 西里尔同形', 'lЗ8ООlЗ8ООО'],
  ['phone 希腊同形', '1３８ΟΟ１３８ΟΟΟ'],
  ['phone Base64 分片', 'MTM4MDA xMzgw MDA='],
  ['phone Base64 嵌套', 'TVRNNE1EQXhNemN3TURBPQ=='],
];

test('编码变形 Fuzz 用例全部命中', () => {
  const missed = CASES.filter(([, text]) => detectSensitive(text).score === 0);
  assert.equal(
    missed.length,
    0,
    missed.map(([name]) => name).join(', '),
  );
});

test('Fuzz 用例不会让普通通知产生误报', () => {
  const normal = [
    '明天下午三点在学院楼开班会，请各班班长准时参加。',
    '请把课程表发到班级群。',
    '图书馆新增了 200 个自习座位。',
    '今天下午的讲座改到线上进行。',
  ];
  const flagged = normal.filter((text) => detectSensitive(text).score > 0);
  assert.equal(flagged.length, 0, flagged.join('\n'));
});
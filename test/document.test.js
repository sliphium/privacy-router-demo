import test from 'node:test';
import assert from 'node:assert/strict';
import JSZip from 'jszip';

import { extractDocumentText, scanDocumentText, recommendDocumentRoute } from '../server/lib/document.js';

async function buildDocx(bodyXml, extraParts = {}) {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`);
  zip.file('_rels/.rels', `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`);
  zip.file('word/document.xml', `<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${bodyXml}<w:sectPr/></w:body></w:document>`);
  for (const [name, xml] of Object.entries(extraParts)) zip.file(name, xml);
  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}

test('文档文本整体检测并脱敏', () => {
  const text = '关于学生名单的通知：张三、李四、王五、赵六，联系人手机 13800138000。';
  const result = scanDocumentText(text, { marker: 'abc123' });

  assert.ok(result.summary.chars > 0);
  assert.ok(result.summary.hits > 0);
  assert.ok(result.summary.criticalHits > 0);
  assert.ok(!result.maskedText.includes('13800138000'));
  assert.ok(result.maskedText.includes('[手机号'));
});

test('普通文档不触发', () => {
  const text = '明天下午三点在学院楼开班会，请各班班长准时参加。';
  const result = scanDocumentText(text);

  assert.equal(result.summary.hits, 0);
  assert.equal(result.summary.maxScore, 0);
});

test('文档路由建议：高敏本地，普通云端', () => {
  const local = recommendDocumentRoute({ criticalHits: 1, hits: 2, maxScore: 90 }, 'campus');
  assert.equal(local.route, 'local');

  const cloud = recommendDocumentRoute({ criticalHits: 0, hits: 0, maxScore: 0 }, 'campus');
  assert.equal(cloud.route, 'cloud');
});

test('docx 脚注、尾注、批注文本纳入扫描范围', async () => {
  const docx = await buildDocx('<w:p><w:r><w:t>正文内容</w:t></w:r></w:p>', {
    'word/footnotes.xml': `<?xml version="1.0"?><w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:footnote w:id="1"><w:p><w:r><w:t>脚注联系手机 13800138000</w:t></w:r></w:p></w:footnote></w:footnotes>`,
    'word/endnotes.xml': `<?xml version="1.0"?><w:endnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:endnote w:id="1"><w:p><w:r><w:t>尾注无关内容</w:t></w:r></w:p></w:endnote></w:endnotes>`,
    'word/comments.xml': `<?xml version="1.0"?><w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="1" w:author="王老师"><w:p><w:r><w:t>批注提醒学号 20230101</w:t></w:r></w:p></w:comment></w:comments>`,
  });

  const text = await extractDocumentText(docx, '材料.docx');
  assert.ok(text.includes('正文内容'));
  assert.ok(text.includes('脚注：'), '应提取脚注');
  assert.ok(text.includes('13800138000'), '脚注中的手机号应被扫描到');
  assert.ok(text.includes('尾注：'), '应提取尾注');
  assert.ok(text.includes('批注：'), '应提取批注');
  assert.ok(text.includes('20230101'), '批注中的学号应被扫描到');

  const scanned = scanDocumentText(text, { marker: 'abc123' });
  assert.ok(scanned.summary.hits >= 2);
  assert.ok(!scanned.maskedText.includes('13800138000'));
});
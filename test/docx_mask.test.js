import test from 'node:test';
import assert from 'node:assert/strict';
import JSZip from 'jszip';

import { maskDocxPreservingFormat } from '../server/lib/docx_mask.js';

const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`;

const ROOT_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;

function documentXml(body) {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}<w:sectPr/></w:body></w:document>`;
}

async function buildDocx(body) {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', CONTENT_TYPES);
  zip.file('_rels/.rels', ROOT_RELS);
  zip.file('word/document.xml', documentXml(body));
  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}

function escapeXml(value) {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function readXml(buffer, name) {
  const zip = await JSZip.loadAsync(buffer);
  return zip.file(name).async('string');
}

test('docx 保留格式脱敏：连续手机号与跨 run 姓名', async () => {
  const body = [
    '<w:p w:rsidR="001"><w:pPr><w:jc w:val="center"/></w:pPr>',
    '<w:r><w:rPr><w:b/></w:rPr><w:t>学生名单：张</w:t></w:r>',
    '<w:r><w:rPr><w:b/></w:rPr><w:t>三、李</w:t></w:r>',
    '<w:r><w:t xml:space="preserve">四、王五，联系电话 13800138000。</w:t></w:r>',
    '</w:p>',
  ].join('');

  const source = await buildDocx(body);
  const { buffer, paragraphsMerged } = await maskDocxPreservingFormat(source, 'abc123');

  const xml = await readXml(buffer, 'word/document.xml');
  assert.ok(!xml.includes('13800138000'), '手机号应被替换');
  assert.ok(!xml.includes('张三'), '跨 run 姓名应被替换');
  assert.ok(xml.includes('[手机号'), '应出现手机号占位符');
  assert.ok(xml.includes('[姓名'), '应出现姓名占位符');
  assert.ok(xml.includes('#abc123'), '占位符应带本次标记');

  assert.equal(paragraphsMerged, 1, '跨 run 段落应合并处理一次');

  assert.ok(xml.includes('<w:pPr><w:jc w:val="center"/></w:pPr>'), '段落属性应保留');
  assert.ok(xml.includes('<w:rPr><w:b/></w:rPr>'), 'run 属性应保留');
  assert.equal((xml.match(/<w:p\b/g) || []).length, 1, '段落数不变');
  assert.equal((xml.match(/<w:r>/g) || []).length, 3, 'run 数不变');
});

test('docx 保留格式脱敏：表格内单元格同步脱敏且结构不变', async () => {
  const body = [
    '<w:tbl><w:tblPr/><w:tr>',
    '<w:tc><w:p><w:r><w:t>姓名</w:t></w:r></w:p></w:tc>',
    '<w:tc><w:p><w:r><w:t>学号</w:t></w:r></w:p></w:tc>',
    '</w:tr><w:tr>',
    '<w:tc><w:p><w:r><w:t>姓名：李四</w:t></w:r></w:p></w:tc>',
    '<w:tc><w:p><w:r><w:t>学号：20230101</w:t></w:r></w:p></w:tc>',
    '</w:tr></w:tbl>',
  ].join('');

  const source = await buildDocx(body);
  const { buffer } = await maskDocxPreservingFormat(source, 'abc123');
  const xml = await readXml(buffer, 'word/document.xml');

  assert.ok(!xml.includes('李四'), '表格姓名应被替换');
  assert.ok(!xml.includes('20230101'), '学号应被替换');
  assert.equal((xml.match(/<w:tr>/g) || []).length, 2, '表格行数不变');
  assert.equal((xml.match(/<w:tc>/g) || []).length, 4, '表格列数不变');
});

test('docx 保留格式脱敏：页眉页脚一并处理', async () => {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', CONTENT_TYPES);
  zip.file('_rels/.rels', ROOT_RELS);
  zip.file('word/document.xml', documentXml('<w:p><w:r><w:t>正文无事发生</w:t></w:r></w:p>'));
  zip.file(
    'word/header1.xml',
    `<?xml version="1.0"?><w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>辅导员 王老师 13900139000</w:t></w:r></w:p></w:hdr>`,
  );
  zip.file(
    'word/footer1.xml',
    `<?xml version="1.0"?><w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>第 1 页</w:t></w:r></w:p></w:ftr>`,
  );
  const source = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });

  const { buffer } = await maskDocxPreservingFormat(source, 'abc123');
  const header = await readXml(buffer, 'word/header1.xml');
  const footer = await readXml(buffer, 'word/footer1.xml');

  assert.ok(!header.includes('13900139000'), '页眉手机号应被替换');
  assert.ok(header.includes('[手机号'), '页眉应出现占位符');
  assert.ok(footer.includes('第 1 页'), '页脚普通文本应保留');
});

test('docx 无敏感内容时原样保留', async () => {
  const source = await buildDocx('<w:p><w:r><w:t>明天下午三点开班会。</w:t></w:r></w:p>');
  const { buffer, runsMasked, paragraphsMerged } = await maskDocxPreservingFormat(source, 'abc123');

  assert.equal(runsMasked, 0);
  assert.equal(paragraphsMerged, 0);

  const xml = await readXml(buffer, 'word/document.xml');
  assert.ok(xml.includes('明天下午三点开班会。'));
});

test('docx 特殊字符转义在脱敏后保持有效', async () => {
  const body = `<w:p><w:r><w:t>${escapeXml('说明：A&B <标签> "引号"，联系 13800138000')}</w:t></w:r></w:p>`;
  const source = await buildDocx(body);
  const { buffer } = await maskDocxPreservingFormat(source, 'abc123');
  const xml = await readXml(buffer, 'word/document.xml');

  assert.ok(xml.includes('A&amp;B &lt;标签&gt; &quot;引号&quot;'), '非敏感文本的转义应正确');
  assert.ok(!xml.includes('13800138000'));

  const zip = await JSZip.loadAsync(buffer);
  assert.ok(zip.file('word/document.xml'), 'document.xml 仍存在');
  assert.ok(zip.file('[Content_Types].xml'), '包结构完整');
});

test('docx 导出清空作者与最后修改者元数据', async () => {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', CONTENT_TYPES);
  zip.file('_rels/.rels', ROOT_RELS);
  zip.file('word/document.xml', documentXml('<w:p><w:r><w:t>普通正文</w:t></w:r></w:p>'));
  zip.file(
    'docProps/core.xml',
    `<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>王小明</dc:creator><cp:lastModifiedBy>王小明</cp:lastModifiedBy><dc:title>学年评奖材料</dc:title></cp:coreProperties>`,
  );
  const source = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });

  const { buffer, metadataCleared } = await maskDocxPreservingFormat(source, 'abc123');
  assert.equal(metadataCleared, 2);

  const core = await readXml(buffer, 'docProps/core.xml');
  assert.ok(!core.includes('王小明'), '作者与最后修改者应被清空');
  assert.ok(core.includes('学年评奖材料'), '标题等非身份字段应保留');
});

test('docx 批注正文同步脱敏', async () => {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', CONTENT_TYPES);
  zip.file('_rels/.rels', ROOT_RELS);
  zip.file('word/document.xml', documentXml('<w:p><w:r><w:t>正文内容</w:t></w:r></w:p>'));
  zip.file(
    'word/comments.xml',
    `<?xml version="1.0"?><w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="1" w:author="王老师"><w:p><w:r><w:t>批注提醒学号 20230101</w:t></w:r></w:p></w:comment></w:comments>`,
  );
  const source = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });

  const { buffer, runsMasked } = await maskDocxPreservingFormat(source, 'abc123');
  const comments = await readXml(buffer, 'word/comments.xml');

  assert.ok(runsMasked >= 1);
  assert.ok(!comments.includes('20230101'), '批注中的学号应被替换');
  assert.ok(comments.includes('[学号'), '批注中应出现占位符');
});

test('docx 导出清空 app.xml 的公司与部门信息', async () => {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', CONTENT_TYPES);
  zip.file('_rels/.rels', ROOT_RELS);
  zip.file('word/document.xml', documentXml('<w:p><w:r><w:t>普通正文</w:t></w:r></w:p>'));
  zip.file(
    'docProps/app.xml',
    `<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>某某大学</Company><Manager>李主任</Manager><Application>Microsoft Office Word</Application></Properties>`,
  );
  const source = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });

  const { buffer, metadataCleared } = await maskDocxPreservingFormat(source, 'abc123');
  assert.equal(metadataCleared, 2);

  const app = await readXml(buffer, 'docProps/app.xml');
  assert.ok(!app.includes('某某大学'), '公司字段应被清空');
  assert.ok(!app.includes('李主任'), '部门负责人字段应被清空');
  assert.ok(app.includes('Microsoft Office Word'), '应用程序字段应保留');
});
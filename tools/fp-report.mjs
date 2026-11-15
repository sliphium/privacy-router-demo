import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { detectSensitive } from '../server/lib/detector.js';
import { probeOllama, reviewWithOllama } from '../server/lib/providers/ollama.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let baseUrl = 'http://127.0.0.1:11434';
let model = 'deepseek-r1:1.5b';

const configPath = path.join(root, 'config.json');
if (fs.existsSync(configPath)) {
  try {
    const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    baseUrl = cfg.ollama?.baseUrl || baseUrl;
    model = cfg.ollama?.model || model;
  } catch {
    // 配置损坏时回退默认值
  }
}

const args = process.argv.slice(2);
let file = '';
let semantic = false;
let threshold = 40;

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === '--semantic') semantic = true;
  else if (arg === '--base') baseUrl = args[++index] || baseUrl;
  else if (arg === '--model') model = args[++index] || model;
  else if (arg === '--threshold') threshold = Number(args[++index]) || threshold;
  else if (!arg.startsWith('--')) file = arg;
}

const target = file || path.join(root, 'test/fixtures/normal-campus-notices.txt');

if (!fs.existsSync(target)) {
  console.error(`文件不存在：${target}`);
  process.exit(1);
}

const lines = fs.readFileSync(target, 'utf8')
  .split('\n')
  .map((line) => line.trim())
  .filter(Boolean);

let flagged = 0;

for (const [index, text] of lines.entries()) {
  const result = detectSensitive(text);
  if (result.score > 0) {
    flagged += 1;
    console.log(`FP #${index + 1}  score=${result.score}  rules=${result.findings.map((item) => item.ruleId).join(',')}`);
    console.log(`   ${text}`);
  }
}

const rate = lines.length === 0 ? 0 : (flagged / lines.length) * 100;
console.log('');
console.log(`规则误报：总计 ${lines.length} 条，误报 ${flagged} 条，误报率 ${rate.toFixed(1)}%`);

if (!semantic) {
  if (flagged === 0 && lines.length > 0) {
    console.log('提示：规则层零误报不等于真实体验零误报，可加 --semantic 用本地模型复核语义层。');
  }
  process.exit(0);
}

const config = { ollama: { baseUrl, model } };
const probe = await probeOllama(config, 1500);
if (!probe.available) {
  console.error(`\n无法连接本地 Ollama（${baseUrl}），请先启动 ollama serve 并拉取 ${model}。`);
  process.exit(1);
}
if (!probe.models.includes(model)) {
  console.error(`\n本地 Ollama 未找到模型 ${model}，当前可用：${probe.models.join(', ') || '无'}。`);
  console.error('请先执行：ollama pull ' + model);
  process.exit(1);
}

console.log('');
console.log(`开始语义复核：模型 ${model}，阈值 ${threshold}，仅复核规则未命中的样本。`);
console.log('1.5b 模型单条可能耗时 30-80 秒，请耐心等待。\n');

let reviewed = 0;
let semanticFp = 0;
let unknown = 0;
const startedAt = Date.now();

for (const [index, text] of lines.entries()) {
  if (detectSensitive(text).score > 0) continue;

  const verdict = await reviewWithOllama({ config, text, timeoutMs: 120000 });
  reviewed += 1;

  if (!verdict) {
    unknown += 1;
    console.log(`UNKNOWN #${index + 1} 模型未返回可解析结果`);
    console.log(`   ${text}`);
    continue;
  }

  if (verdict.score >= threshold) {
    semanticFp += 1;
    console.log(`SEM-FP #${index + 1}  score=${verdict.score}  reason=${verdict.reason}`);
    console.log(`   ${text}`);
  }
}

const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
const semanticRate = reviewed === 0 ? 0 : (semanticFp / reviewed) * 100;

console.log('');
console.log(`语义误报：复核 ${reviewed} 条，误报 ${semanticFp} 条，误报率 ${semanticRate.toFixed(1)}%；无法判定 ${unknown} 条；耗时 ${elapsed}s`);
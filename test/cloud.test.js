import test from 'node:test';
import assert from 'node:assert/strict';

import { resolveCloudEndpoint, inspectCloudConfig, describeCloudStatus } from '../server/lib/providers/cloud.js';

test('云端 endpoint 兼容 /v1、裸域名与完整端点', () => {
  assert.equal(
    resolveCloudEndpoint('https://api.openai.com/v1'),
    'https://api.openai.com/v1/chat/completions',
  );
  assert.equal(
    resolveCloudEndpoint('https://api.openai.com/v1/'),
    'https://api.openai.com/v1/chat/completions',
  );
  assert.equal(
    resolveCloudEndpoint('https://api.deepseek.com'),
    'https://api.deepseek.com/v1/chat/completions',
  );
  assert.equal(
    resolveCloudEndpoint('https://api.deepseek.com/v1/chat/completions'),
    'https://api.deepseek.com/v1/chat/completions',
  );
  assert.equal(
    resolveCloudEndpoint('https://gateway.example.com/openai/v1'),
    'https://gateway.example.com/openai/v1/chat/completions',
  );
});

test('云端 endpoint 拒绝非法地址', () => {
  assert.equal(resolveCloudEndpoint(''), null);
  assert.equal(resolveCloudEndpoint('not a url'), null);
  assert.equal(resolveCloudEndpoint('ftp://example.com/v1'), null);
});

test('云端配置校验区分「有 key」与「真正可用」', () => {
  const base = {
    cloud: { baseUrl: 'https://api.openai.com/v1', model: 'gpt-4o-mini', apiKey: 'sk-test-1234' },
  };

  const ok = inspectCloudConfig(base);
  assert.equal(ok.configured, true);
  assert.equal(ok.valid, true);
  assert.equal(ok.endpoint, 'https://api.openai.com/v1/chat/completions');
  assert.equal(ok.reason, '');

  const noKey = inspectCloudConfig({ cloud: { ...base.cloud, apiKey: '' } });
  assert.equal(noKey.configured, false);
  assert.equal(noKey.valid, false);
  assert.match(noKey.reason, /API Key/);

  const badUrl = inspectCloudConfig({ cloud: { ...base.cloud, baseUrl: 'not a url' } });
  assert.equal(badUrl.configured, false);
  assert.equal(badUrl.valid, false);
  assert.match(badUrl.reason, /http/);

  const noModel = inspectCloudConfig({ cloud: { ...base.cloud, model: '' } });
  assert.equal(noModel.configured, true);
  assert.equal(noModel.valid, false);
  assert.match(noModel.reason, /模型/);
});

test('云端错误码给出可操作提示', () => {
  assert.match(describeCloudStatus(401, ''), /API Key/);
  assert.match(describeCloudStatus(403, ''), /API Key/);
  assert.match(describeCloudStatus(404, ''), /模型名/);
  assert.match(describeCloudStatus(429, ''), /限流/);
  assert.match(describeCloudStatus(500, 'boom'), /500/);
});
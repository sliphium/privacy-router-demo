const $ = (id) => document.getElementById(id);

const ROUTE_META = {
  idle: { label: '待命', color: '#334155', target: '待定' },
  local: { label: '本地处理', color: '#34d399', target: '本地 Ollama' },
  'cloud-sanitized': { label: '脱敏上云', color: '#fbbf24', target: '云端 API（脱敏）' },
  cloud: { label: '云端直连', color: '#60a5fa', target: '云端 API' },
  blocked: { label: '已阻断', color: '#f87171', target: '不出端' },
};

const SAMPLES = {
  local: '帮我整理这份学生名单：张三、李四、王五、赵六，学号 2023010101，期末成绩和绩点一起汇总，准备评奖学金。',
  sanitized: '帮我查一下手机号 13800138000 的归属地和运营商，用一句话说明。',
  cloud: '用三句话解释向量数据库的检索原理，并给一个电商场景的例子。',
};

const state = {
  config: null,
  health: null,
  history: [],
  chatting: false,
};

const els = {
  messages: $('messages'),
  emptyState: $('emptyState'),
  input: $('input'),
  sendBtn: $('sendBtn'),
  badge: $('decisionBadge'),
  scoreRing: $('scoreRing'),
  scoreValue: $('scoreValue'),
  routeName: $('routeName'),
  routeReason: $('routeReason'),
  routeTarget: $('routeTarget'),
  scoreMarker: $('scoreMarker'),
  zoneMask: $('zoneMask'),
  zoneLocal: $('zoneLocal'),
  sanitizeLabelBar: $('sanitizeLabelBar'),
  localLabelBar: $('localLabelBar'),
  evidenceCount: $('evidenceCount'),
  evidenceList: $('evidenceList'),
  outboundText: $('outboundText'),
  auditList: $('auditList'),
  chatHint: $('chatHint'),
  localStatus: $('localStatus'),
  cloudStatus: $('cloudStatus'),
  toast: $('toast'),
};

let toastTimer = null;

async function getJson(url) {
  const response = await fetch(url, { headers: { accept: 'application/json' } });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `请求失败（${response.status}）`);
  return payload;
}

async function putJson(url, payload) {
  const response = await fetch(url, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `保存失败（${response.status}）`);
  return data;
}

function toast(message, isError = false) {
  els.toast.textContent = message;
  els.toast.classList.toggle('error', isError);
  els.toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.classList.remove('show'), 2600);
}

function setPill(element, status, label) {
  element.classList.remove('ok', 'warn', 'down');
  if (status) element.classList.add(status);
  element.querySelector('.status-label').textContent = label;
}

function scrollMessages() {
  els.messages.scrollTop = els.messages.scrollHeight;
}

function hideEmptyState() {
  const node = els.messages.querySelector('.empty-state');
  if (node) node.remove();
}

function appendMessage(role, text) {
  hideEmptyState();
  const wrapper = document.createElement('div');
  wrapper.className = `message ${role}`;
  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = text;
  wrapper.appendChild(bubble);
  els.messages.appendChild(wrapper);
  scrollMessages();
  return wrapper;
}

function attachRouteChip(message, route, label) {
  let chip = message.querySelector('.route-chip');
  if (!chip) {
    chip = document.createElement('span');
    chip.className = 'route-chip';
    message.insertBefore(chip, message.querySelector('.bubble'));
  }
  chip.dataset.route = route;
  chip.textContent = label;
}

function renderMeta(meta) {
  const view = ROUTE_META[meta.route] || ROUTE_META.idle;
  els.badge.textContent = meta.routeLabel;
  els.badge.dataset.route = meta.route;
  els.scoreValue.textContent = String(meta.score);
  els.scoreRing.style.setProperty('--score', String(meta.score));
  els.scoreRing.style.setProperty('--ring', view.color);
  els.routeName.textContent = view.label;
  els.routeName.style.color = view.color;
  els.routeReason.textContent = meta.reason;
  els.routeTarget.textContent = view.target;
  els.routeTarget.dataset.route = meta.route;
  els.scoreMarker.style.left = `${Math.min(100, Math.max(0, meta.score))}%`;
  renderZones(meta.thresholds);
  renderEvidence(meta.findings);
  renderOutbound(meta);

  if (meta.route === 'local') {
    els.chatHint.textContent = '本次原文未外发，全程在本机处理';
  } else if (meta.route === 'blocked') {
    els.chatHint.textContent = '涉密任务已阻断，未产生任何外部请求';
  } else if (meta.route === 'cloud-sanitized') {
    els.chatHint.textContent = `已脱敏 ${meta.masks.length} 处实体后上云`;
  } else {
    els.chatHint.textContent = '未发现敏感特征，直连云端';
  }

  const contextTainted = meta.context && meta.context.taintedTurns > 0 && meta.context.turns > 1;
  const currentTainted = meta.context ? meta.context.lastScore > 0 : true;

  if (meta.criticalHit && currentTainted) {
    els.chatHint.textContent = '命中高敏内容，已按最高级别留在本机';
  } else if (contextTainted) {
    els.chatHint.textContent = `已检查 ${meta.context.turns} 轮上下文，涉密历史一并留在本机`;
  } else if (meta.profile === 'campus' && meta.route === 'local') {
    els.chatHint.textContent = '校园严格策略：涉敏内容已留在本机';
  }
}

function renderZones(thresholds) {
  if (!thresholds) return;
  const local = Math.min(100, Math.max(1, Number(thresholds.local)));
  const sanitize = Math.min(local - 1, Math.max(0, Number(thresholds.sanitize)));
  els.zoneMask.style.left = `${sanitize}%`;
  els.zoneMask.style.width = `${Math.max(0, local - sanitize)}%`;
  els.zoneLocal.style.left = `${local}%`;
  els.zoneLocal.style.right = '0';
  els.sanitizeLabelBar.textContent = `脱敏 ${sanitize}`;
  els.localLabelBar.textContent = `本地 ${local}`;
}

function renderEvidence(findings) {
  els.evidenceCount.textContent = String(findings.length);
  els.evidenceList.textContent = '';
  if (findings.length === 0) {
    const item = document.createElement('li');
    item.className = 'muted';
    item.textContent = '暂无命中，未发现敏感实体或商业机密特征';
    els.evidenceList.appendChild(item);
    return;
  }
  for (const finding of findings) {
    const item = document.createElement('li');
    item.className = 'evidence-item';
    item.dataset.sev = finding.severity;
    if (finding.redacted) item.classList.add('redacted');

    const head = document.createElement('div');
    head.className = 'ev-head';
    const label = document.createElement('span');
    label.className = 'ev-label';
    label.textContent = finding.label;
    const weight = document.createElement('span');
    weight.className = 'ev-weight';
    weight.textContent = finding.redacted ? '细节已隐去' : `权重 ${finding.weight} · ${finding.count} 处`;
    const tier = document.createElement('span');
    tier.className = 'ev-tier';
    tier.dataset.tier = finding.tier || 'normal';
    tier.textContent = finding.tier === 'critical' ? '高敏' : finding.tier === 'sensitive' ? '敏感' : '一般';
    head.append(label, tier, weight);

    const preview = document.createElement('p');
    preview.className = 'ev-preview';
    preview.textContent = finding.redacted ? '（细节已隐去）' : finding.preview;

    const reason = document.createElement('p');
    reason.className = 'ev-reason';
    reason.textContent = finding.reason;

    item.append(head, preview, reason);
    els.evidenceList.appendChild(item);
  }
}

function renderOutbound(meta) {
  els.outboundText.textContent = '';
  if (meta.route === 'local') {
    const span = document.createElement('span');
    span.className = 'none';
    span.textContent = '未外发 · 原文仅在本机由 Ollama 处理';
    els.outboundText.appendChild(span);
    return;
  }
  if (meta.route === 'blocked') {
    const span = document.createElement('span');
    span.className = 'none';
    span.textContent = '未外发 · 请求已阻断（fail-closed）';
    els.outboundText.appendChild(span);
    return;
  }
  const text = String(meta.outboundText || '').slice(0, 1200);
  const parts = text.split(/(<[A-Z]+_\d+>)/g);
  for (const part of parts) {
    if (!part) continue;
    if (/^<[A-Z]+_\d+>$/.test(part)) {
      const span = document.createElement('span');
      span.className = 'hl';
      span.textContent = part;
      els.outboundText.appendChild(span);
    } else {
      els.outboundText.appendChild(document.createTextNode(part));
    }
  }
}

async function streamChat(payload, handlers) {
  const response = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail.error || `请求失败（${response.status}）`);
  }
  if (!response.body) throw new Error('当前浏览器不支持流式响应');

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    buffer = buffer.replace(/\r\n/g, '\n');
    let boundary = buffer.indexOf('\n\n');
    while (boundary !== -1) {
      const block = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      dispatchEventBlock(block, handlers);
      boundary = buffer.indexOf('\n\n');
    }
  }
  if (buffer.trim()) dispatchEventBlock(buffer, handlers);
}

function dispatchEventBlock(block, handlers) {
  let event = 'message';
  const dataLines = [];
  for (const line of block.split('\n')) {
    if (line.startsWith('event:')) event = line.slice(6).trim();
    else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
  }
  if (dataLines.length === 0) return;
  let data;
  try {
    data = JSON.parse(dataLines.join('\n'));
  } catch {
    return;
  }
  if (typeof handlers[event] === 'function') handlers[event](data);
}

async function sendMessage(text) {
  const content = String(text || '').trim();
  if (!content || state.chatting) return;

  state.chatting = true;
  els.sendBtn.disabled = true;
  els.input.value = '';
  els.badge.textContent = '判定中';
  els.badge.dataset.route = 'idle';

  appendMessage('user', content);
  state.history.push({ role: 'user', content });

  const assistant = appendMessage('assistant', '正在判定敏感度并选择路由…');
  const bubble = assistant.querySelector('.bubble');
  bubble.classList.add('streaming');

  let fullText = '';
  let finished = false;

  try {
    await streamChat({ messages: state.history }, {
      meta(meta) {
        renderMeta(meta);
        attachRouteChip(assistant, meta.route, meta.routeLabel);
        bubble.textContent = '';
      },
      delta(data) {
        fullText += data.text;
        bubble.textContent = fullText;
        scrollMessages();
      },
      final(data) {
        fullText = data.text;
        bubble.textContent = fullText;
        if (data.unresolved > 0) {
          toast(`有 ${data.unresolved} 个未识别占位符，已隐藏`, true);
        }
        scrollMessages();
      },
      error(data) {
        assistant.classList.add('error');
        bubble.textContent = fullText ? `${fullText}\n\n⚠ ${data.message}` : `⚠ ${data.message}`;
        bubble.classList.remove('streaming');
        toast(data.message, true);
        scrollMessages();
      },
      done() {
        finished = true;
        bubble.classList.remove('streaming');
        if (fullText) state.history.push({ role: 'assistant', content: fullText });
        loadAudit();
      },
    });
  } catch (error) {
    assistant.classList.add('error');
    bubble.textContent = `请求失败：${error.message}`;
    bubble.classList.remove('streaming');
    toast(error.message, true);
  } finally {
    if (!finished) bubble.classList.remove('streaming');
    state.chatting = false;
    els.sendBtn.disabled = false;
    els.input.focus();
  }
}

async function loadConfig() {
  const config = await getJson('/api/config');
  state.config = config;
  $('demoToggle').checked = Boolean(config.demoMode);
  $('profileSelect').value = config.privacyProfile === 'campus' ? 'campus' : 'enterprise';
  $('strictToggle').checked = Boolean(config.strictMode);
  $('ollamaModel').value = config.ollama.model;
  $('ollamaUrl').value = config.ollama.baseUrl;
  $('cloudModel').value = config.cloud.model;
  $('cloudUrl').value = config.cloud.baseUrl;
  $('cloudKey').value = config.cloud.apiKey || '';
  $('cloudKey').dataset.masked = config.cloud.apiKey || '';
  $('semanticToggle').checked = Boolean(config.semanticReview);
  $('fallbackToggle').checked = Boolean(config.allowLocalFallback);
  $('timeoutSec').value = String(Math.round((config.timeoutMs || 300000) / 1000));
  $('localThreshold').value = String(config.thresholds.local);
  $('sanitizeThreshold').value = String(config.thresholds.sanitize);
  syncThresholdLabels();
  renderZones(config.thresholds);
}

function syncThresholdLabels() {
  let local = Number($('localThreshold').value);
  let sanitize = Number($('sanitizeThreshold').value);
  if (sanitize >= local) {
    sanitize = Math.max(0, local - 1);
    $('sanitizeThreshold').value = String(sanitize);
  }
  $('localLabel').textContent = String(local);
  $('sanitizeLabel').textContent = String(sanitize);
  renderZones({ local, sanitize });
}

function collectConfig() {
  return {
    privacyProfile: $('profileSelect').value,
    demoMode: $('demoToggle').checked,
    strictMode: $('strictToggle').checked,
    thresholds: {
      local: Number($('localThreshold').value),
      sanitize: Number($('sanitizeThreshold').value),
    },
    ollama: {
      baseUrl: $('ollamaUrl').value.trim(),
      model: $('ollamaModel').value.trim(),
    },
    cloud: {
      baseUrl: $('cloudUrl').value.trim(),
      model: $('cloudModel').value.trim(),
      apiKey: $('cloudKey').value.trim() || $('cloudKey').dataset.masked || '',
    },
    semanticReview: $('semanticToggle').checked,
    allowLocalFallback: $('fallbackToggle').checked,
    timeoutMs: Math.max(5, Math.min(1800, Number($('timeoutSec').value) || 300)) * 1000,
  };
}

async function saveConfig(silent = false) {
  try {
    const saved = await putJson('/api/config', collectConfig());
    state.config = saved;
    $('cloudKey').value = saved.cloud.apiKey || '';
    $('cloudKey').dataset.masked = saved.cloud.apiKey || '';
    if (!silent) toast('配置已保存');
    loadHealth();
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadHealth() {
  try {
    const health = await getJson('/api/health');
    state.health = health;
    const demo = health.availability.mode === 'demo';
    const localLabel = demo ? '本地 Ollama · 演示' : `本地 Ollama · ${health.ollama.model}`;
    const cloudLabel = demo ? '云端 API · 演示' : `云端 API · ${health.cloud.model}`;

    if (health.availability.local) setPill(els.localStatus, 'ok', localLabel);
    else setPill(els.localStatus, 'down', '本地 Ollama 未连接');

    if (health.availability.cloud) setPill(els.cloudStatus, 'ok', cloudLabel);
    else if (!health.cloud.configured) setPill(els.cloudStatus, 'warn', '云端 Key 未配置');
    else setPill(els.cloudStatus, 'down', '云端 API 不可用');

    if (demo) {
      els.chatHint.textContent = '演示模式：本地与云端均为模拟应答';
    }
  } catch {
    setPill(els.localStatus, 'down', '本地状态未知');
    setPill(els.cloudStatus, 'down', '云端状态未知');
  }
}

async function loadAudit() {
  try {
    const data = await getJson('/api/audit?limit=30');
    renderAudit(data.records || []);
  } catch {
    return;
  }
}

function renderAudit(records) {
  els.auditList.textContent = '';
  if (records.length === 0) {
    const item = document.createElement('li');
    item.className = 'muted';
    item.textContent = '暂无记录';
    els.auditList.appendChild(item);
    return;
  }

  for (const record of records) {
    const item = document.createElement('li');
    item.className = 'audit-item';
    item.dataset.route = record.route;

    const top = document.createElement('div');
    top.className = 'audit-top';
    const route = document.createElement('span');
    route.className = 'audit-route';
    route.textContent = record.routeLabel || record.route;
    const time = document.createElement('span');
    time.className = 'audit-time';
    time.textContent = formatTime(record.ts);
    top.append(route, time);

    const main = document.createElement('div');
    main.className = 'audit-main';
    main.textContent = `敏感度 ${record.score} · ${record.findings.length} 条证据 · ${record.durationMs ?? 0}ms${record.ok ? '' : ' · 失败'}`;

    const preview = document.createElement('div');
    preview.className = 'audit-preview';
    preview.textContent = buildPreview(record);

    item.append(top, main, preview);
    els.auditList.appendChild(item);
  }
}

function buildPreview(record) {
  if (record.route === 'local') return '原文未外发，仅本机处理';
  if (record.route === 'blocked') return record.error || '请求已阻断';
  if (!record.outboundHash) return '无外发内容';
  return `外发内容未落盘 · ${record.outboundLength} 字符 · 指纹 ${record.outboundHash.slice(0, 10)}`;
}

function formatTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString('zh-CN', { hour12: false });
}

function resetConversation() {
  if (state.chatting) return;
  state.history = [];
  els.messages.textContent = '';

  const empty = document.createElement('div');
  empty.className = 'empty-state';
  const title = document.createElement('p');
  title.className = 'empty-title';
  title.textContent = '新对话已开始';
  const desc = document.createElement('p');
  desc.className = 'empty-desc';
  desc.textContent = '上下文已清空，上一轮的涉密内容不会再随本次请求外发。';
  empty.append(title, desc);
  els.messages.appendChild(empty);

  els.badge.textContent = '待命';
  els.badge.dataset.route = 'idle';
  els.chatHint.textContent = '发送前自动判定敏感度';
  els.input.focus();
}

function bindEvents() {
  $('newChat').addEventListener('click', resetConversation);
  $('composer').addEventListener('submit', (event) => {
    event.preventDefault();
    sendMessage(els.input.value);
  });

  els.input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      sendMessage(els.input.value);
    }
    if (event.key === 'Escape') {
      els.input.value = '';
    }
  });

  document.querySelectorAll('.sample').forEach((button) => {
    button.addEventListener('click', () => {
      const key = button.dataset.sample;
      const sample = SAMPLES[key];
      if (!sample) return;
      els.input.value = sample;
      sendMessage(sample);
    });
  });

  $('localThreshold').addEventListener('input', syncThresholdLabels);
  $('sanitizeThreshold').addEventListener('input', syncThresholdLabels);

  $('demoToggle').addEventListener('change', () => saveConfig(true));
  $('profileSelect').addEventListener('change', () => saveConfig(true));
  $('strictToggle').addEventListener('change', () => saveConfig(true));
  $('saveConfig').addEventListener('click', () => saveConfig(false));

  $('refreshAudit').addEventListener('click', loadAudit);
  $('clearAudit').addEventListener('click', async () => {
    if (!window.confirm('确认清空本地审计日志？')) return;
    try {
      await fetch('/api/audit/clear', { method: 'POST' });
      await loadAudit();
      toast('审计日志已清空');
    } catch {
      toast('清空失败', true);
    }
  });

  $('cloudKey').addEventListener('focus', (event) => {
    if (event.target.value === event.target.dataset.masked) {
      event.target.select();
    }
  });
}

async function init() {
  bindEvents();
  try {
    await loadConfig();
  } catch (error) {
    toast(`配置加载失败：${error.message}`, true);
  }
  loadHealth();
  loadAudit();
  setInterval(loadHealth, 15000);
  els.input.focus();
}

init();
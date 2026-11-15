export function normalizeThresholds(thresholds) {
  const raw = thresholds || {};
  const local = clamp(Number(raw.local), 1, 100, 40);
  let sanitize = clamp(Number(raw.sanitize), 0, 99, 10);
  if (sanitize >= local) sanitize = Math.max(0, local - 1);
  return { local, sanitize };
}

function clamp(value, min, max, fallback) {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.round(value)));
}

export function initialDecision({ score, findings, config }) {
  const { local, sanitize } = normalizeThresholds(config.thresholds);
  const profile = config.privacyProfile === 'campus' ? 'campus' : 'enterprise';
  const criticalHit = findings.some((finding) => finding.tier === 'critical');

  if (criticalHit) {
    return {
      route: 'local',
      profile,
      criticalHit: true,
      reason: '命中高敏内容，按最高敏感级别处理，数据不出端',
      thresholds: { local, sanitize },
    };
  }

  if (profile === 'campus' && findings.length > 0) {
    return {
      route: 'local',
      profile,
      criticalHit: false,
      reason: '校园强隐私模式：命中敏感证据，涉敏任务一律留在本机',
      thresholds: { local, sanitize },
    };
  }

  if (config.strictMode && findings.length > 0) {
    return {
      route: 'local',
      profile,
      criticalHit: false,
      reason: '严格模式：命中任意敏感证据，强制本地处理',
      thresholds: { local, sanitize },
    };
  }

  if (score >= local) {
    return {
      route: 'local',
      profile,
      criticalHit: false,
      reason: `敏感度 ${score} 达到本地阈值 ${local}，数据不出端`,
      thresholds: { local, sanitize },
    };
  }

  if (score >= sanitize) {
    return {
      route: 'cloud-sanitized',
      profile,
      criticalHit: false,
      reason: `敏感度 ${score} 落在脱敏区间 [${sanitize}, ${local})，脱敏后上云`,
      thresholds: { local, sanitize },
    };
  }

  return {
    route: 'cloud',
    profile,
    criticalHit: false,
    reason: `敏感度 ${score} 低于脱敏阈值 ${sanitize}，直连云端口径`,
    thresholds: { local, sanitize },
  };
}

export function applyRescan(decision, rescanScore, config) {
  const { local } = normalizeThresholds(config.thresholds);
  if (decision.route !== 'cloud-sanitized') return decision;
  if (rescanScore < local) return decision;
  return {
    ...decision,
    route: 'local',
    upgraded: true,
    reason: `脱敏后复检得分 ${rescanScore} 仍达到本地阈值 ${local}，升级为本地处理`,
  };
}

export function applyAvailability(decision, availability, config) {
  if (decision.route === 'local') {
    if (availability.local) return decision;
    return {
      ...decision,
      route: 'blocked',
      reason: '本地模型不可达，涉密任务已阻断（fail-closed），绝不会改走云端',
    };
  }

  if (availability.cloud) return decision;

  if (config.allowLocalFallback !== false && availability.local) {
    return {
      ...decision,
      route: 'local',
      degraded: true,
      reason: '云端不可达，按安全优先策略降级到本地处理',
    };
  }

  return {
    ...decision,
    route: 'blocked',
    reason: '云端不可达且本地不可用，请求已阻断',
  };
}

export const ROUTE_LABELS = {
  local: '本地处理',
  'cloud-sanitized': '脱敏上云',
  cloud: '云端直连',
  blocked: '已阻断',
};
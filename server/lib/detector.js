const ID_CARD_PATTERN = /(?<![0-9A-Za-z])(\d{6}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?![0-9A-Za-z])/g;
const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const ID_CHECKSUM = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];

const BANK_CARD_PATTERN = /(?<![0-9])(?:4\d{15}|5[1-5]\d{14}|62\d{14,17}|3[47]\d{13})(?![0-9])/g;

const SURNAMES = '王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋蔡余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤';

const ENTITY_RULES = [
  {
    id: 'private-key',
    label: 'PEM 私钥',
    category: 'secret',
    severity: 'critical',
    weight: 96,
    token: 'PRIVATEKEY',
    reason: '命中 PEM 私钥块，可直接用于身份冒用或解密通信',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{16,}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  },
  {
    id: 'cloud-key',
    label: '云厂商/平台密钥',
    category: 'secret',
    severity: 'critical',
    weight: 92,
    token: 'KEY',
    reason: '命中云厂商或代码托管平台的访问密钥格式',
    pattern: /\b(?:AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]{12,20}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b/g,
  },
  {
    id: 'connection-string',
    label: '数据库连接串',
    category: 'secret',
    severity: 'high',
    weight: 86,
    token: 'DSN',
    reason: '命中带凭据的数据库连接串',
    pattern: /\b(?:jdbc:[a-z0-9]+:\/\/|mongodb(?:\+srv)?:\/\/|mysql:\/\/|postgres(?:ql)?:\/\/|redis:\/\/|amqp:\/\/)[^\s"'`]+/gi,
  },
  {
    id: 'id-card',
    label: '身份证号',
    category: 'pii',
    severity: 'high',
    weight: 88,
    token: 'IDCARD',
    reason: '命中居民身份证号且校验位有效',
    pattern: ID_CARD_PATTERN,
    validate: (value) => {
      const digits = value.slice(0, 17).split('').map(Number);
      let sum = 0;
      for (let i = 0; i < 17; i += 1) sum += digits[i] * ID_WEIGHTS[i];
      return ID_CHECKSUM[sum % 11] === value[17].toUpperCase();
    },
  },
  {
    id: 'bank-card',
    label: '银行卡号',
    category: 'pii',
    severity: 'high',
    weight: 82,
    token: 'BANKCARD',
    reason: '命中银行卡号且 Luhn 校验通过',
    pattern: BANK_CARD_PATTERN,
    validate: (value) => {
      let sum = 0;
      let double = false;
      for (let i = value.length - 1; i >= 0; i -= 1) {
        let digit = Number(value[i]);
        if (double) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
        double = !double;
      }
      return sum % 10 === 0;
    },
  },
  {
    id: 'student-id',
    label: '学号/考生号',
    category: 'campus',
    severity: 'high',
    weight: 84,
    token: 'STUDENTID',
    reason: '命中带学号/考生号上下文的学籍编号',
    pattern: /(?<!\d)\d{8,14}(?!\d)/g,
    validate: (value, source, index) => {
      if (/^1[3-9]\d{9}$/.test(value)) return false;
      const around = source.slice(Math.max(0, index - 12), index + value.length + 12);
      return /(学号|学籍号|考生号|工号|编号)/.test(around);
    },
  },
  {
    id: 'dorm-room',
    label: '宿舍/床位信息',
    category: 'campus',
    severity: 'medium',
    weight: 62,
    token: 'DORM',
    reason: '命中宿舍楼栋或床位编号，可用于定位到具体学生',
    pattern: /(?<![A-Za-z0-9])(?:[A-Za-z]?\d{1,2}[栋幢号楼]\s*\d{2,4}(?:室|房间)?|\d{1,3}\s*号床)(?![0-9])/g,
  },
  {
    id: 'phone',
    label: '手机号',
    category: 'pii',
    severity: 'medium',
    weight: 58,
    token: 'PHONE',
    reason: '命中中国大陆手机号',
    pattern: /(?<!\d)1[3-9]\d{9}(?!\d)/g,
  },
  {
    id: 'email',
    label: '邮箱地址',
    category: 'pii',
    severity: 'low',
    weight: 34,
    token: 'EMAIL',
    reason: '命中邮箱地址，可用于身份关联',
    pattern: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])/g,
  },
  {
    id: 'internal-ip',
    label: '内网地址',
    category: 'infra',
    severity: 'medium',
    weight: 46,
    token: 'IP',
    reason: '命中内网 IP，泄露内部网络拓扑',
    pattern: /(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)/g,
  },
  {
    id: 'internal-domain',
    label: '内部域名',
    category: 'infra',
    severity: 'medium',
    weight: 52,
    token: 'DOMAIN',
    reason: '命中内部域名或内网主机名',
    pattern: /(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+(?:corp|internal|intranet|lan|local)(?![A-Za-z0-9-])/gi,
  },
  {
    id: 'entropy-token',
    label: '高熵随机串',
    category: 'secret',
    severity: 'high',
    weight: 64,
    token: 'TOKEN',
    reason: '命中高熵随机串，疑似口令或令牌',
    pattern: /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{24,80}(?![A-Za-z0-9+/=_-])/g,
    validate: (value) => looksRandom(value),
  },
];

const NAME_RULE = {
  id: 'student-name',
  label: '学生姓名',
  category: 'campus',
  severity: 'high',
  weight: 66,
  token: 'NAME',
  reason: '命中带校园上下文的真实姓名',
};

const NAME_LIST_RULE = {
  id: 'name-list',
  label: '学生名单',
  category: 'campus',
  severity: 'critical',
  weight: 90,
  token: 'NAME',
  reason: '命中多姓名并列的名单结构，可直接识别到具体学生',
};

const KEYWORD_RULES = [
  {
    id: 'campus-mental',
    label: '个人健康与心理信息',
    category: 'health',
    severity: 'critical',
    weight: 96,
    display: 'hidden',
    reason: '涉及个人健康或心理状况，按最高保护级别处理',
    keywords: ['心理测评', '心理普查', '心理咨询', '心理健康', '心理档案', '心理危机', '心理辅导', '危机干预', '抑郁', '焦虑', '双相', '强迫症', '精神科', '服药治疗', '自伤', '自残', '自杀', '轻生', '病史', '残疾'],
  },
  {
    id: 'campus-aid',
    label: '资助与困难认定',
    category: 'campus',
    severity: 'critical',
    weight: 88,
    reason: '涉及家庭经济困难认定或资助信息，属于高度敏感的个人信息',
    keywords: ['贫困生', '建档立卡', '低保', '助学金', '助学贷款', '困难认定', '家庭经济困难', '勤工助学', '学费减免', '绿色通道'],
  },
  {
    id: 'campus-discipline',
    label: '处分与违纪记录',
    category: 'campus',
    severity: 'critical',
    weight: 88,
    reason: '涉及处分、违纪或学术不端记录',
    keywords: ['处分', '记过', '留校察看', '开除学籍', '通报批评', '违纪', '作弊', '学术不端', '学业预警'],
  },
  {
    id: 'campus-roster',
    label: '学生名单与档案',
    category: 'campus',
    severity: 'high',
    weight: 84,
    reason: '命中学生名单、通讯录或信息登记表等结构化个人信息',
    keywords: ['学生名单', '学生信息', '学生花名册', '花名册', '通讯录', '信息统计表', '登记表', '评奖评优', '公示名单', '学生档案', '学籍信息', '班级群', '家长群', '成绩单'],
  },
  {
    id: 'campus-party',
    label: '党团与政审材料',
    category: 'campus',
    severity: 'high',
    weight: 78,
    reason: '涉及入党入团、政审或组织谈话材料',
    keywords: ['入党申请', '入党积极', '发展对象', '预备党员', '政审', '函调', '推优', '思想汇报', '团组织关系', '谈话记录'],
  },
  {
    id: 'campus-academic',
    label: '学业与奖惩数据',
    category: 'campus',
    severity: 'high',
    weight: 72,
    reason: '涉及成绩、绩点、排名或奖助评定数据',
    keywords: ['绩点', '学分', '排名', '挂科', '补考', '重修', '保研', '综测', '奖学金', '评奖', '推免'],
  },
  {
    id: 'campus-address',
    label: '家庭住址',
    category: 'campus',
    severity: 'high',
    weight: 74,
    reason: '涉及家庭住址、户籍或生源地信息',
    keywords: ['家庭住址', '家庭地址', '住址', '家住', '户籍地', '生源地', '现居住地', '家庭所在地'],
  },
  {
    id: 'campus-guardian',
    label: '家长/监护人信息',
    category: 'campus',
    severity: 'medium',
    weight: 56,
    reason: '涉及家长或监护人联系方式与家庭情况',
    keywords: ['家长电话', '家长联系方式', '监护人', '家长姓名', '家庭情况', '家庭成员'],
  },
  {
    id: 'legal-doc',
    label: '合同与法务',
    category: 'business',
    severity: 'high',
    weight: 68,
    reason: '涉及合同、法务或保密约定内容',
    keywords: ['合同', '甲方', '乙方', '补充协议', '保密协议', 'nda', '招标', '投标', '报价单', '违约', '诉讼', '裁决书'],
  },
  {
    id: 'finance-data',
    label: '财务与经营',
    category: 'business',
    severity: 'high',
    weight: 72,
    reason: '涉及财务数据或未公开经营指标',
    keywords: ['营收', '毛利率', '净利润', '现金流', '财报', '预算表', '银行账号', '开户行', '税号', '发票号', '融资', '估值', '对赌', '成本结构'],
  },
  {
    id: 'hr-data',
    label: '人事与薪酬',
    category: 'pii',
    severity: 'high',
    weight: 70,
    reason: '涉及员工薪酬、绩效或人事档案',
    keywords: ['简历', '薪酬', '工资条', '绩效', '背调', '员工名单', '组织架构', '离职', '竞业', '期权授予', '候选人'],
  },
  {
    id: 'trade-secret',
    label: '内部机密',
    category: 'business',
    severity: 'critical',
    weight: 78,
    reason: '涉及内部机密、未公开规划或核心资产',
    keywords: ['绝密', '机密', '内部资料', '未公开', '商业计划', '战略规划', '客户名单', '供应商名单', '源代码', '算法配方', '专利交底', '路演材料'],
  },
  {
    id: 'code-block',
    label: '完整代码块',
    category: 'code',
    severity: 'high',
    weight: 74,
    reason: '包含完整代码块，可能暴露私有实现',
    keywords: [],
    pattern: /```[\s\S]{60,}?```/g,
  },
];

const CONTEXT_RULES = [
  {
    id: 'campus-task-context',
    label: '校园隐私任务语境',
    category: 'campus',
    severity: 'high',
    weight: 82,
    reason: '任务描述同时出现学生主体与隐私字段，按涉敏任务处理',
    subjects: ['学生', '同学', '班级', '辅导员', '新生', '毕业生', '家长', '学员'],
    objects: ['名字', '姓名', '住址', '地址', '电话', '手机', '身份证', '信息', '名单', '表格', 'excel', '隐私', '数据', '档案', '通讯录', '花名册'],
  },
];

const CRITICAL_RULE_IDS = new Set([
  'private-key', 'cloud-key', 'connection-string', 'id-card', 'bank-card', 'student-id', 'entropy-token',
  'name-list', 'campus-roster', 'campus-address',
  'campus-mental', 'campus-aid', 'campus-discipline', 'campus-party',
  'legal-doc', 'finance-data', 'hr-data', 'trade-secret', 'code-block',
]);
const SENSITIVE_RULE_IDS = new Set([
  'phone', 'email', 'internal-ip', 'internal-domain', 'dorm-room',
  'campus-academic', 'campus-guardian', 'campus-task-context', 'student-name',
]);

for (const rule of [...ENTITY_RULES, ...KEYWORD_RULES, ...CONTEXT_RULES, NAME_RULE, NAME_LIST_RULE]) {
  if (CRITICAL_RULE_IDS.has(rule.id)) rule.tier = 'critical';
  else if (SENSITIVE_RULE_IDS.has(rule.id)) rule.tier = 'sensitive';
  else rule.tier = 'normal';
}

const HEALTH_REDACTION = {
  ruleId: 'protected-health',
  label: '个人健康与心理信息',
  category: 'health',
  severity: 'critical',
  tier: 'critical',
  weight: 96,
  reason: '涉及个人健康或心理状况，按最高保护级别处理，细节不对外展示',
  count: 0,
  preview: '（细节已隐去）',
  maskable: false,
  redacted: true,
};

function collectMatches(text, pattern, validate) {
  const matches = [];
  pattern.lastIndex = 0;
  let match = pattern.exec(text);
  while (match !== null) {
    if (match[0].length === 0) {
      pattern.lastIndex += 1;
      match = pattern.exec(text);
      continue;
    }
    if (!validate || validate(match[0], text, match.index)) {
      matches.push({ value: match[0], index: match.index, length: match[0].length });
    }
    match = pattern.exec(text);
  }
  return matches;
}

function collectNames(source) {
  const re = new RegExp(`[${SURNAMES}][\\u4e00-\\u9fa5]{1,2}`, 'g');
  const contextRe = /(学生|同学|姓名|名单|联系人|家长|班级|名叫|叫做|学员)/;
  const blockRe = /^(?:老师|总|经理|主任|院长|书记|师傅|公司|集团|银行|大学|学院)$/;
  const candidates = [];
  const singles = [];

  let match = re.exec(source);
  while (match !== null) {
    const value = match[0];
    const after = source.slice(match.index + value.length, match.index + value.length + 6);
    if (blockRe.test(after)) {
      match = re.exec(source);
      continue;
    }
    const before = source.slice(Math.max(0, match.index - 12), match.index);
    const around = `${before}${value}${source.slice(match.index + value.length, match.index + value.length + 12)}`;
    const span = { value, index: match.index, length: value.length };
    candidates.push(span);
    if (contextRe.test(around)) singles.push(span);
    match = re.exec(source);
  }

  const lines = new Map();
  for (const span of candidates) {
    const start = source.lastIndexOf('\n', span.index) + 1;
    if (!lines.has(start)) lines.set(start, []);
    lines.get(start).push(span);
  }

  const listMatches = [];
  for (const spans of lines.values()) {
    if (spans.length >= 3) listMatches.push(...spans);
  }

  const result = [];
  if (singles.length > 0) result.push({ rule: NAME_RULE, matches: dedupeSpans(singles) });
  if (listMatches.length > 0) result.push({ rule: NAME_LIST_RULE, matches: dedupeSpans(listMatches) });
  return result;
}

function dedupeSpans(spans) {
  const seen = new Set();
  const out = [];
  for (const span of spans) {
    const key = `${span.index}:${span.length}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(span);
  }
  return out;
}

function collectContextMatches(source) {
  const lower = source.toLowerCase();
  const results = [];
  for (const rule of CONTEXT_RULES) {
    const hits = [];
    for (const word of rule.subjects) {
      const index = lower.indexOf(word.toLowerCase());
      if (index !== -1) hits.push({ value: source.slice(index, index + word.length), index, length: word.length });
    }
    const objectHits = [];
    for (const word of rule.objects) {
      let from = 0;
      let index = lower.indexOf(word.toLowerCase(), from);
      while (index !== -1) {
        objectHits.push({ value: source.slice(index, index + word.length), index, length: word.length });
        from = index + word.length;
        index = lower.indexOf(word.toLowerCase(), from);
      }
    }
    const matchedSubjects = new Set(hits.map((hit) => hit.value));
    if (matchedSubjects.size >= 1 && objectHits.length > 0) {
      results.push({ rule, matches: [...hits, ...objectHits] });
    }
  }
  return results;
}

function looksRandom(value) {
  if (/^https?:\/\//i.test(value)) return false;
  if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(value)) return false;
  if (/(?:[A-Za-z0-9-]+\.)+(?:com|cn|net|org|corp|internal|local|io)\b/i.test(value)) return false;
  const classes = (/[a-z]/.test(value) ? 1 : 0) + (/[A-Z]/.test(value) ? 1 : 0)
    + (/[0-9]/.test(value) ? 1 : 0) + (/[+/=_-]/.test(value) ? 1 : 0);
  if (classes < 3) return false;
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy >= 3.6;
}

function overlaps(a, b) {
  return a.index < b.index + b.length && b.index < a.index + a.length;
}

function maskPreview(rule, value) {
  if (rule.display === 'hidden') return HEALTH_REDACTION.preview;
  const visible = (head, tail) => {
    if (value.length <= head + tail) return '*'.repeat(Math.max(4, value.length));
    return `${value.slice(0, head)}${'*'.repeat(Math.max(4, value.length - head - tail))}${value.slice(-tail)}`;
  };
  switch (rule.id) {
    case 'phone':
      return visible(3, 4);
    case 'id-card':
      return visible(6, 4);
    case 'bank-card':
      return visible(4, 4);
    case 'student-id':
      return visible(4, 3);
    case 'email': {
      const at = value.indexOf('@');
      if (at <= 0) return '***';
      return `${value[0]}***${value.slice(at)}`;
    }
    case 'internal-ip':
      return visible(3, 3);
    case 'private-key':
    case 'cloud-key':
    case 'connection-string':
    case 'entropy-token':
      return visible(4, 4);
    case 'student-name':
    case 'name-list':
      return `${value[0]}${'*'.repeat(Math.max(1, value.length - 1))}`;
    default:
      return `${value.slice(0, 24)}${value.length > 24 ? '…' : ''}`;
  }
}

export function detectSensitive(text) {
  const source = typeof text === 'string' ? text : '';
  if (source.trim().length === 0) {
    return { score: 0, findings: [] };
  }

  const candidates = [];

  for (const rule of ENTITY_RULES) {
    const matches = collectMatches(source, rule.pattern, rule.validate);
    if (matches.length > 0) candidates.push({ rule, matches });
  }

  candidates.push(...collectNames(source));
  candidates.push(...collectContextMatches(source));

  for (const rule of KEYWORD_RULES) {
    if (rule.pattern) {
      const matches = collectMatches(source, rule.pattern);
      if (matches.length > 0) candidates.push({ rule, matches });
      continue;
    }
    const matches = [];
    const lower = source.toLowerCase();
    for (const keyword of rule.keywords) {
      let from = 0;
      let index = lower.indexOf(keyword.toLowerCase(), from);
      while (index !== -1) {
        matches.push({ value: source.slice(index, index + keyword.length), index, length: keyword.length });
        from = index + keyword.length;
        index = lower.indexOf(keyword.toLowerCase(), from);
      }
    }
    if (matches.length > 0) candidates.push({ rule, matches });
  }

  candidates.sort((a, b) => {
    const weightDiff = b.rule.weight - a.rule.weight;
    if (weightDiff !== 0) return weightDiff;
    return b.matches[0].length - a.matches[0].length;
  });

  const accepted = [];
  const occupied = [];
  for (const candidate of candidates) {
    const kept = candidate.matches.filter((match) => {
      const span = { index: match.index, length: match.length };
      if (occupied.some((taken) => overlaps(taken, span))) return false;
      occupied.push(span);
      return true;
    });
    if (kept.length > 0) {
      accepted.push({
        ruleId: candidate.rule.id,
        label: candidate.rule.label,
        category: candidate.rule.category,
        severity: candidate.rule.severity,
        tier: candidate.rule.tier,
        weight: candidate.rule.weight,
        reason: candidate.rule.reason,
        token: candidate.rule.token || null,
        maskable: Boolean(candidate.rule.token),
        display: candidate.rule.display || 'masked',
        matches: kept,
        count: kept.length,
        preview: maskPreview(candidate.rule, kept[0].value),
      });
    }
  }

  const score = scoreFindings(accepted);
  return { score, findings: accepted };
}

export function detectConversation(messages) {
  const inspected = [];
  const findings = [];
  let score = 0;
  let taintedTurns = 0;

  messages.forEach((message, index) => {
    const result = detectSensitive(message.content);
    inspected.push({
      index,
      role: message.role,
      score: result.score,
      findings: result.findings,
    });
    if (result.findings.length > 0) taintedTurns += 1;
    if (result.score > score) score = result.score;
    findings.push(...result.findings);
  });

  return { score, findings, messages: inspected, taintedTurns };
}

export function scoreFindings(findings) {
  if (findings.length === 0) return 0;
  const weights = findings.map((finding) => finding.weight).sort((a, b) => b - a);
  const base = weights[0];
  const rest = weights.slice(1).reduce((sum, weight) => sum + weight, 0);
  const categoryBonus = new Set(findings.map((finding) => finding.category)).size >= 3 ? 8 : 0;
  return Math.min(100, Math.round(base + rest * 0.18 + categoryBonus));
}

export function toPublicFindings(findings) {
  return findings.map((finding) => {
    if (finding.display === 'hidden') {
      return { ...HEALTH_REDACTION, weight: finding.weight };
    }
    return {
      ruleId: finding.ruleId,
      label: finding.label,
      category: finding.category,
      severity: finding.severity,
      tier: finding.tier,
      weight: finding.weight,
      reason: finding.reason,
      count: finding.count,
      preview: finding.preview,
      maskable: finding.maskable,
      redacted: false,
    };
  });
}

export const RULE_IDS = [...ENTITY_RULES, ...KEYWORD_RULES, NAME_RULE, NAME_LIST_RULE].map((rule) => rule.id);
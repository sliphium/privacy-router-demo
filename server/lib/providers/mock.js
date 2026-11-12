const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function excerpt(text, limit = 60) {
  const clean = String(text || '').replace(/\s+/g, ' ').trim();
  if (!clean) return '（空输入）';
  return clean.length > limit ? `${clean.slice(0, limit)}…` : clean;
}

function composeMock({ route, config, question, masks, score }) {
  const placeholders = (masks || []).map((mask) => mask.placeholder);
  const maskHint = placeholders.length > 0
    ? `已将 ${placeholders.length} 处敏感实体替换为占位符（${placeholders.slice(0, 3).join('、')}${placeholders.length > 3 ? ' 等' : ''}），云端只收到脱敏文本，响应返回后再在本机回填。`
    : '';

  if (route === 'local') {
    return [
      `〔本地 Ollama · 模拟应答｜模型 ${config.ollama.model}〕`,
      '',
      `这条请求的敏感度为 ${score}/100，已判定为涉密，全程在本机闭环处理，原文没有发出任何网络请求。`,
      '',
      '为避免二次暴露，本机应答不复述原始细节，也不对任何个人做标签化判断。建议这样处理：',
      '1. 只在本机核对名单、成绩、资助或健康类材料，用“该同学”“相关材料”指代；',
      '2. 把结论压缩成不含身份信息的工作要点，再决定是否需要对外同步；',
      '3. 涉及心理或健康内容时，不转述、不评价、不扩散，必要时走学校正式的心理支持渠道。',
    ].join('\n');
  }

  if (route === 'cloud-sanitized') {
    return [
      `〔云端 API · 模拟应答｜模型 ${config.cloud.model}｜已脱敏〕`,
      '',
      `该请求敏感度为 ${score}/100，落在脱敏区间。${maskHint}`,
      '',
      `云端看到的问题大意是：「${excerpt(question)}」`,
      '',
      '这正是端云协同的折中点：保留任务语义，剥离可识别信息，让云端算力处理结构化部分，回填与还原只发生在你的机器上。',
    ].join('\n');
  }

  return [
    `〔云端 API · 模拟应答｜模型 ${config.cloud.model}〕`,
    '',
    `该请求敏感度为 ${score}/100，未发现敏感实体，按策略直连云端，以获取最强推理能力。`,
    '',
    `你问的是：「${excerpt(question)}」`,
    '',
    '真实模式下，这里会返回云端模型的流式输出；API Key 只保存在本地后端，浏览器永远看不到明文。',
  ].join('\n');
}

export async function* streamMock({ route, config, question, masks, score, signal }) {
  const text = composeMock({ route, config, question, masks, score });
  const chunks = text.match(/[\s\S]{1,6}/g) || [];

  for (const chunk of chunks) {
    if (signal?.aborted) return;
    yield chunk;
    await sleep(6);
  }
}
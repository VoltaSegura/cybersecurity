import { AI_CONFIG, aiConfigured, type AiConfig } from '../config';
import { PiiEngine } from '../pii/engine';
import type { LeakEvent, SinkKind } from '../taint/runtime';

/** Resumo SEM dado pessoal: é só isso que a camada de IA recebe. */
export interface SanitizedFinding { category: string; sink: SinkKind; severity: string; occurrences: number }
export interface CitizenAlert {
  titulo: string; severity: string; category: string; sink: SinkKind; occurrences: number;
  riscoReal: string; oQueFazer: string; correcaoTecnica: string; fonte: 'llm' | 'offline';
}

const DESTINO: Record<SinkKind, string> = {
  log: 'nos registros internos do sistema',
  errorReport: 'em relatórios de erro compartilhados com a equipe',
  analytics: 'em ferramentas de análise de uso',
  llm: 'em um serviço externo de inteligência artificial',
};
const TEXTO: Record<string, { titulo: string; risco: string; fazer: string; fix: string }> = {
  localizacao: {
    titulo: 'Seus trajetos podem revelar onde você mora',
    risco: 'Quem repete o mesmo trajeto toda noite expõe o endereço de casa e a rotina de saída. Esses dados não deveriam ser guardados.',
    fazer: 'Evite preencher endereço de casa como origem ou destino se não for necessário e use o GPS só quando precisar.',
    fix: 'Remover origem, destino e coordenadas de logs; registrar apenas duração e quantidade de opções.',
  },
  contato: {
    titulo: 'Seu e-mail ou telefone ficaria ligado ao seu histórico',
    risco: 'Contato vinculado a trajetos facilita rastrear uma pessoa e abre espaço para golpes e assédio.',
    fazer: 'Desconfie de mensagens que citem seus trajetos e revise os dados da sua conta no app.',
    fix: 'Trocar o e-mail por um identificador anônimo (pseudonimização) em logs e métricas.',
  },
  credencial: {
    titulo: 'Sua senha ou sessão poderia ser usada por outra pessoa',
    risco: 'Uma senha ou token legível permite que qualquer pessoa com acesso aos registros entre na sua conta.',
    fazer: 'Troque sua senha se receber um aviso de incidente e use senhas diferentes em cada serviço.',
    fix: 'Nunca registrar senhas ou tokens; mascarar cabeçalhos de autenticação antes de qualquer saída.',
  },
  identificador: {
    titulo: 'Seu CPF poderia circular fora do cadastro',
    risco: 'O CPF é a chave para abrir contas e pedir crédito em seu nome; fora do local protegido, aumenta o risco de fraude.',
    fazer: 'Evite informar CPF em campos de texto livre e acompanhe seu nome em serviços de proteção ao crédito.',
    fix: 'Aplicar a regra de CPF (com validação) antes de enviar texto a qualquer serviço externo.',
  },
  saude: {
    titulo: 'Uma informação de saúde sua sairia do app',
    risco: 'Dado de saúde é dado sensível: se exposto, pode gerar discriminação e constrangimento difíceis de reverter.',
    fazer: 'Evite descrever condições de saúde em campos de texto livre; fale com o suporte por canal oficial.',
    fix: 'Bloquear texto livre com termos de saúde antes do envio ao LLM e mascarar o trecho.',
  },
};
const GENERICO = {
  titulo: 'Um dado seu estaria exposto', risco: 'Dados pessoais fora do lugar protegido aumentam o risco de uso indevido.',
  fazer: 'Revise as informações que você compartilha no app.', fix: 'Sanitizar a saída antes de gravar ou enviar.',
};

export function offlineAlert(f: SanitizedFinding): CitizenAlert {
  const t = TEXTO[f.category] ?? GENERICO;
  return {
    titulo: t.titulo, severity: f.severity, category: f.category, sink: f.sink, occurrences: f.occurrences,
    riscoReal: `${t.risco} Isso aparecia ${DESTINO[f.sink]}.`, oQueFazer: t.fazer, correcaoTecnica: t.fix, fonte: 'offline',
  };
}

/** Agrupa eventos por categoria + destino, guardando só contagens (nada de valores). */
export function sanitizeEvents(events: LeakEvent[]): SanitizedFinding[] {
  const order = ['critical', 'high', 'medium', 'low'];
  const map = new Map<string, SanitizedFinding>();
  for (const e of events) {
    const k = `${e.category}|${e.sink}`;
    const cur = map.get(k) ?? { category: e.category, sink: e.sink, severity: e.severity, occurrences: 0 };
    cur.occurrences++;
    if (order.indexOf(e.severity) < order.indexOf(cur.severity)) cur.severity = e.severity;
    map.set(k, cur);
  }
  return [...map.values()].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}

/** Guarda de saída: nenhum prompt com dado pessoal pode ir ao LLM. */
export function assertNoPii(prompt: string, engine = new PiiEngine()): void {
  if (engine.scan(prompt).length) throw new Error('Prompt bloqueado: contém dado pessoal.');
}

const SYSTEM =
  'Você escreve alertas curtos para cidadãos que usam um app de rotas, em português simples e sem jargão. ' +
  'Nunca prometa segurança total nem fale em conformidade legal. Responda SOMENTE com um array JSON: um objeto por achado, ' +
  'na mesma ordem recebida, cada um com as chaves titulo, riscoReal, oQueFazer e correcaoTecnica (no máximo 2 frases cada).';

type FetchFn = typeof fetch;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Uma única chamada ao Gemini para TODOS os achados (economiza cota e evita limite de requisições por minuto). */
async function askGemini(findings: SanitizedFinding[], cfg: AiConfig, fetchFn: FetchFn, retryDelaysMs: number[]): Promise<unknown[]> {
  const user = `Achados técnicos (sem dados pessoais): ${JSON.stringify(findings)}. Devolva um array JSON com exatamente ${findings.length} objetos.`;
  assertNoPii(SYSTEM + user); // guarda de saída: nada de PII sai para o LLM
  const url = `${cfg.baseUrl}/models/${cfg.model.replace(/^models\//, '')}:generateContent`;
  const init = {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-goog-api-key': cfg.apiKey },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: SYSTEM }] },
      contents: [{ role: 'user', parts: [{ text: user }] }],
      generationConfig: { maxOutputTokens: 2048, temperature: 0.4, responseMimeType: 'application/json' },
    }),
  };
  for (let attempt = 0; ; attempt++) {
    const res = await fetchFn(url, { ...init, signal: AbortSignal.timeout(45_000) });
    if (res.status === 429 && attempt < retryDelaysMs.length) { await sleep(retryDelaysMs[attempt]); continue; } // limite do plano gratuito
    if (!res.ok) {
      const hint = res.status === 404 ? ' — modelo inexistente: rode "npm run ai:models" e ajuste GEMINI_MODEL' : '';
      throw new Error(`API respondeu ${res.status}: ${(await res.text()).slice(0, 200)}${hint}`);
    }
    const data = (await res.json()) as {
      candidates?: { finishReason?: string; content?: { parts?: { text?: string; thought?: boolean }[] } }[];
      promptFeedback?: { blockReason?: string };
    };
    const text = (data.candidates?.[0]?.content?.parts ?? []).filter((p) => p.text && !p.thought).map((p) => p.text).join('');
    if (!text) throw new Error(`resposta vazia (${data.promptFeedback?.blockReason ?? data.candidates?.[0]?.finishReason ?? 'sem motivo'})`);
    const arr = JSON.parse(text.slice(text.indexOf('['), text.lastIndexOf(']') + 1)); // tolera cercas ```json
    if (!Array.isArray(arr)) throw new Error('resposta não é um array JSON');
    return arr;
  }
}

const valid = (j: any): boolean => !!j && ['titulo', 'riscoReal', 'oQueFazer', 'correcaoTecnica'].every((k) => typeof j[k] === 'string' && j[k]);

/** Traduz achados em alertas com o Gemini. Sem chave, ou se a chamada falhar, usa o modo offline e avisa no stderr. */
export async function translateFindings(
  findings: SanitizedFinding[], cfg: AiConfig = AI_CONFIG, fetchFn: FetchFn = fetch, retryDelaysMs: number[] = [3000, 8000],
): Promise<CitizenAlert[]> {
  if (!aiConfigured(cfg) || !findings.length) return findings.map(offlineAlert);
  try {
    const out = await askGemini(findings, cfg, fetchFn, retryDelaysMs);
    return findings.map((f, i) => {
      const j = out[i] as any;
      if (!valid(j)) return offlineAlert(f); // item faltando ou malformado: usa o modelo local só para ele
      return { ...offlineAlert(f), titulo: j.titulo, riscoReal: j.riscoReal, oQueFazer: j.oQueFazer, correcaoTecnica: j.correcaoTecnica, fonte: 'llm' as const };
    });
  } catch (e) {
    const cause = (e as { cause?: { code?: string } }).cause?.code;
    console.error(`[IA] falha ao chamar o Gemini (${(e as Error).message}${cause ? ` / ${cause}` : ''}${(e as Error).message === 'fetch failed' ? ' — verifique a internet, proxy ou firewall' : ''}); usando modo offline.`);
    return findings.map(offlineAlert);
  }
}

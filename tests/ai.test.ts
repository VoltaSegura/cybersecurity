import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertNoPii, offlineAlert, sanitizeEvents, translateFindings } from '../src/ai/remediation';
import { fullAudit } from '../src/audit/run';
import { aiConfigured, type AiConfig } from '../src/config';
import { PiiEngine } from '../src/pii/engine';

const f1 = { category: 'localizacao', sink: 'log', severity: 'high', occurrences: 3 } as const;
const f2 = { category: 'credencial', sink: 'log', severity: 'critical', occurrences: 2 } as const;
const cfg: AiConfig = { baseUrl: 'https://api.test/v1beta', apiKey: 'chave-teste', model: 'modelo-x' };
const semChave: AiConfig = { ...cfg, apiKey: '' };
const item = (t: string) => ({ titulo: t, riscoReal: 'R', oQueFazer: 'F', correcaoTecnica: 'C' });
const gemini = (text: string, status = 200) =>
  new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text }] } }] }), { status });
const quiet = async <T>(fn: () => Promise<T>) => { const o = console.error; console.error = () => {}; try { return await fn(); } finally { console.error = o; } };

test('sem chave → modo offline', async () => {
  assert.equal(aiConfigured(semChave), false);
  const [al] = await translateFindings([f1], semChave);
  assert.equal(al.fonte, 'offline');
  assert.match(al.riscoReal, /registros internos/);
});
test('com chave → UMA chamada ao Gemini para todos os achados', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const fake = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return gemini('```json\n' + JSON.stringify([item('A'), item('B')]) + '\n```');
  }) as unknown as typeof fetch;
  const out = await translateFindings([f1, f2], cfg, fake);
  assert.equal(calls.length, 1);
  assert.deepEqual(out.map((a) => [a.titulo, a.fonte]), [['A', 'llm'], ['B', 'llm']]);
  assert.equal(calls[0].url, 'https://api.test/v1beta/models/modelo-x:generateContent');
  assert.equal((calls[0].init.headers as Record<string, string>)['x-goog-api-key'], 'chave-teste');
  const body = JSON.parse(String(calls[0].init.body));
  assert.equal(body.generationConfig.responseMimeType, 'application/json');
  assert.deepEqual(new PiiEngine().scan(JSON.stringify(body)), []);
});
test('item faltando na resposta → só ele usa o modo offline', async () => {
  const fake = (async () => gemini(JSON.stringify([item('A')]))) as unknown as typeof fetch;
  const out = await translateFindings([f1, f2], cfg, fake);
  assert.deepEqual(out.map((a) => a.fonte), ['llm', 'offline']);
});
test('429 (limite do plano gratuito) → tenta de novo e funciona', async () => {
  let n = 0;
  const fake = (async () => (++n === 1 ? new Response('limite', { status: 429 }) : gemini(JSON.stringify([item('A')])))) as unknown as typeof fetch;
  const [al] = await translateFindings([f1], cfg, fake, [0]);
  assert.equal(n, 2);
  assert.equal(al.fonte, 'llm');
});
test('falha da API → modo offline sem quebrar', async () => {
  const fake = (async () => new Response('erro', { status: 400 })) as unknown as typeof fetch;
  const [al] = await quiet(() => translateFindings([f1], cfg, fake, []));
  assert.equal(al.fonte, 'offline');
});
test('entrada da IA nunca contém dado pessoal', () => {
  const json = JSON.stringify(sanitizeEvents(fullAudit().antes.events));
  assert.deepEqual(new PiiEngine().scan(json), []);
});
test('guarda de saída bloqueia prompt com PII', () => {
  assert.throws(() => assertNoPii('CPF 529.982.247-25'), /bloqueado/);
  assert.doesNotThrow(() => assertNoPii(JSON.stringify(offlineAlert({ ...f1, category: 'saude', sink: 'llm' }))));
});

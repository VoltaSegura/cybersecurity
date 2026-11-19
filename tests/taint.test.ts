import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fullAudit } from '../src/audit/run';
import { PiiEngine } from '../src/pii/engine';
import { analyzeSource } from '../src/taint/static';
import { computeRisk } from '../src/risk/risk';

const a = fullAudit();

test('dinâmico: app vulnerável vaza para os 4 tipos de destino', () => {
  const sinks = new Set(a.antes.events.map((e) => e.sink));
  assert.deepEqual([...sinks].sort(), ['analytics', 'errorReport', 'llm', 'log']);
});
test('dinâmico: bloqueio em tempo real impede qualquer vazamento', () => {
  assert.ok(a.bloqueio.events.length > 0 && a.bloqueio.events.every((e) => e.action === 'blocked'));
  const raw = ['529.982.247-25', 'Volta@2026!', 'agatha.santos@example.com', '-23.5614'];
  for (const o of a.bloqueio.outputs) for (const r of raw) assert.ok(!o.text.includes(r), `${r} vazou`);
});
test('dinâmico: app corrigido não vaza nada', () => {
  assert.equal(a.depois.events.length, 0);
});
test('estático: acha os fluxos do vulnerável e nenhum no corrigido', () => {
  assert.equal(a.estatica.antes.length, 7);
  assert.equal(a.estatica.depois.length, 0);
});
test('estático: sanitizador interrompe o fluxo; atribuição propaga', () => {
  const eng = new PiiEngine();
  const limpo = 'export function h(req:any,ctx:any){const {x}=req.body; ctx.logger.info(ctx.privacy.redact(x));}';
  const sujo = 'export function h(req:any,ctx:any){const {x}=req.body; let y; y = `a ${x}`; ctx.logger.info(y);}';
  assert.equal(analyzeSource('l.ts', limpo, eng).length, 0);
  assert.equal(analyzeSource('s.ts', sujo, eng).length, 1);
});
test('risco: vulnerável é crítico, corrigido é zero e score fica em 0–100', () => {
  assert.equal(a.risco.antes.level, 'Crítico');
  assert.equal(a.risco.depois.score, 0);
  assert.ok(a.risco.antes.score <= 100);
  assert.equal(computeRisk([]).score, 0);
});

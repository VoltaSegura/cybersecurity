import type { LeakEvent, SinkKind } from '../taint/runtime';
import type { Severity } from '../pii/types';

/**
 * Risco Cidadão (0–100): mede o risco aos DADOS PESSOAIS de quem usa o app — nunca risco de bairro ou território.
 * Cada vazamento único (categoria + origem + destino) pesa: severidade × exposição do destino × (1,25 se dado sensível).
 * Score = 100 × (1 − e^(−soma/K)). Vazamentos bloqueados em tempo real não entram na soma.
 */
export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 10, high: 6, medium: 3, low: 1 };
export const SINK_EXPOSURE: Record<SinkKind, number> = { llm: 1, analytics: 0.9, errorReport: 0.8, log: 0.6 };
export const K = 40;
export type Level = 'Baixo' | 'Moderado' | 'Alto' | 'Crítico';

export interface Risk {
  score: number; level: Level; leaks: number; blocked: number;
  bySink: Record<string, number>; byCategory: Record<string, number>;
}

export function levelOf(score: number): Level {
  return score >= 75 ? 'Crítico' : score >= 50 ? 'Alto' : score >= 25 ? 'Moderado' : 'Baixo';
}

export function computeRisk(events: LeakEvent[]): Risk {
  const unique = new Map<string, LeakEvent>();
  for (const e of events.filter((x) => x.action === 'detected')) {
    unique.set(`${e.category}|${e.origin}|${e.masked}|${e.sink}`, e);
  }
  let sum = 0;
  const bySink: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  for (const e of unique.values()) {
    sum += SEVERITY_WEIGHT[e.severity] * SINK_EXPOSURE[e.sink] * (e.sensitive ? 1.25 : 1);
    bySink[e.sink] = (bySink[e.sink] ?? 0) + 1;
    byCategory[e.category] = (byCategory[e.category] ?? 0) + 1;
  }
  const score = Math.round(100 * (1 - Math.exp(-sum / K)));
  const blocked = new Set(events.filter((x) => x.action === 'blocked').map((e) => `${e.origin}|${e.masked}|${e.sink}`)).size;
  return { score, level: levelOf(score), leaks: unique.size, blocked, bySink, byCategory };
}

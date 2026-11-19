import { fileURLToPath } from 'node:url';
import { PiiEngine } from '../pii/engine';
import { runScenarios, type Mode, type RunResult } from '../taint/runtime';
import { analyzeDir } from '../taint/static';
import { computeRisk } from '../risk/risk';
import { SCENARIOS } from '../app/scenarios';
import * as vulnerable from '../app/vulnerable/routes';
import * as secure from '../app/secure/routes';
import type { Handler } from '../app/types';

export const APP_DIRS = {
  vulnerable: fileURLToPath(new URL('../app/vulnerable', import.meta.url)),
  secure: fileURLToPath(new URL('../app/secure', import.meta.url)),
};
const H = (m: object) => m as Record<string, Handler>;

export const runVariant = (variant: 'vulnerable' | 'secure', mode: Mode): RunResult =>
  runScenarios(variant, H(variant === 'vulnerable' ? vulnerable : secure), SCENARIOS, mode);

export function fullAudit() {
  const engine = new PiiEngine();
  const antes = runVariant('vulnerable', 'monitor');
  const bloqueio = runVariant('vulnerable', 'enforce');
  const depois = runVariant('secure', 'monitor');
  return {
    antes, bloqueio, depois,
    risco: { antes: computeRisk(antes.events), bloqueio: computeRisk(bloqueio.events), depois: computeRisk(depois.events) },
    estatica: {
      antes: analyzeDir(APP_DIRS.vulnerable, engine, 'app/vulnerable'),
      depois: analyzeDir(APP_DIRS.secure, engine, 'app/secure'),
    },
    ruleCount: engine.ruleCount,
  };
}

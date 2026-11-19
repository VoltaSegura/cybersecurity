import { createHash } from 'node:crypto';
import { PiiEngine, mask } from '../pii/engine';
import type { Category, Severity } from '../pii/types';
import type { Ctx, Handler, Req } from '../app/types';

export type SinkKind = 'log' | 'errorReport' | 'analytics' | 'llm';
export type Mode = 'monitor' | 'enforce';

export interface LeakEvent {
  scenario: string;
  sink: SinkKind;
  origin: string;          // de onde o dado nasceu (ex.: req.body.origem)
  ruleId: string;
  category: Category;
  severity: Severity;
  sensitive: boolean;
  masked: string;
  action: 'detected' | 'blocked';
  via: 'taint' | 'pii-engine';
}
export interface SinkOutput { scenario: string; sink: SinkKind; text: string; status: 'limpo' | 'vazou' | 'bloqueado' }

interface Tag { origin: string; ruleId: string; category: Category; severity: Severity; sensitive: boolean }

/** Taint por valor: marca (na ENTRADA) todo dado pessoal e detecta se ele chega a um destino inseguro. */
export class TaintTracker {
  private tags = new Map<string, Tag>();
  constructor(private engine: PiiEngine) {}

  /** Fonte: registra cada dado pessoal encontrado na requisição, com sua origem. */
  ingest(source: string, data: unknown): void {
    for (const f of this.engine.scanObject(data)) {
      if (f.value.length < 3) continue;
      this.tags.set(f.value, {
        origin: `${source}.${f.path ?? ''}`.replace(/\.$/, ''),
        ruleId: f.ruleId, category: f.category, severity: f.severity, sensitive: f.sensitive,
      });
    }
  }

  /** Destino: procura valores marcados (propagados por concatenação/template) e PII não rastreado. */
  check(text: string): Omit<LeakEvent, 'scenario' | 'sink' | 'action'>[] {
    const out: Omit<LeakEvent, 'scenario' | 'sink' | 'action'>[] = [];
    const tracedValues: string[] = [];
    for (const [value, t] of this.tags) {
      if (!text.includes(value)) continue;
      tracedValues.push(value);
      out.push({ ...t, masked: mask(value), via: 'taint' });
    }
    for (const f of this.engine.scan(text)) {
      if (tracedValues.some((v) => f.value.includes(v) || v.includes(f.value))) continue;
      out.push({
        origin: 'não rastreada', ruleId: f.ruleId, category: f.category, severity: f.severity,
        sensitive: f.sensitive, masked: f.masked, via: 'pii-engine',
      });
    }
    return out;
  }

  /** Sanitizador: troca valores marcados e PII detectado por etiquetas. */
  redact(text: string): string {
    let out = text;
    for (const [value, t] of [...this.tags].sort((a, b) => b[0].length - a[0].length)) {
      out = out.split(value).join(`[BLOQUEADO:${t.origin}]`);
    }
    return this.engine.redact(out);
  }
}

export class SinkGuard {
  events: LeakEvent[] = [];
  outputs: SinkOutput[] = [];
  constructor(private tracker: TaintTracker, private mode: Mode, private scenario: string) {}

  emit(sink: SinkKind, payload: unknown): string {
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const leaks = this.tracker.check(text);
    const action = this.mode === 'enforce' ? 'blocked' : 'detected';
    for (const l of leaks) this.events.push({ ...l, scenario: this.scenario, sink, action });
    const emitted = this.mode === 'enforce' && leaks.length ? this.tracker.redact(text) : text;
    this.outputs.push({ scenario: this.scenario, sink, text: emitted, status: leaks.length === 0 ? 'limpo' : this.mode === 'enforce' ? 'bloqueado' : 'vazou' });
    return emitted;
  }
}

export function createContext(guard: SinkGuard, tracker: TaintTracker): Ctx {
  const to = (k: SinkKind) => (...a: unknown[]) => void guard.emit(k, a.length === 1 ? a[0] : a);
  return {
    logger: { info: to('log'), debug: to('log'), error: to('log') },
    errors: { report: to('errorReport') },
    analytics: { track: (name, props) => void guard.emit('analytics', { name, props }) },
    llm: { ask: (prompt) => `[resposta simulada do LLM — ${guard.emit('llm', prompt).length} caracteres recebidos]` },
    privacy: {
      redact: (t) => tracker.redact(t),
      pseudonymize: (v) => 'anon_' + createHash('sha256').update(v).digest('hex').slice(0, 8),
    },
  };
}

export interface Scenario { name: string; handler: string; req: Req }
export interface RunResult { variant: string; mode: Mode; events: LeakEvent[]; outputs: SinkOutput[] }

export function runScenarios(variant: string, handlers: Record<string, Handler>, scenarios: Scenario[], mode: Mode): RunResult {
  const engine = new PiiEngine();
  const result: RunResult = { variant, mode, events: [], outputs: [] };
  for (const s of scenarios) {
    const tracker = new TaintTracker(engine);
    tracker.ingest('req.body', s.req.body);
    tracker.ingest('req.headers', s.req.headers);
    tracker.ingest('req.user', s.req.user);
    const guard = new SinkGuard(tracker, mode, s.name);
    handlers[s.handler](s.req, createContext(guard, tracker));
    result.events.push(...guard.events);
    result.outputs.push(...guard.outputs);
  }
  return result;
}

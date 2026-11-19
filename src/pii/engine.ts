import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { VALIDATORS } from './validators';
import type { Finding, KeyHint, PiiRule, RuleSet, Severity } from './types';

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function loadRuleSet(path = fileURLToPath(new URL('./rules.json', import.meta.url))): RuleSet {
  return JSON.parse(readFileSync(path, 'utf8')) as RuleSet;
}

export function mask(value: string): string {
  return value.length <= 6 ? '•••' : '•'.repeat(Math.min(value.length - 2, 10)) + value.slice(-2);
}

export class PiiEngine {
  private compiled: { rule: PiiRule; re: RegExp }[] = [];
  private hints: { re: RegExp; hint: KeyHint }[] = [];

  constructor(ruleSet: RuleSet = loadRuleSet()) {
    ruleSet.rules.forEach((r) => this.addRule(r));
    ruleSet.keyHints.forEach((h) => this.addKeyHint(h));
  }

  /** Registra uma nova regra em tempo de execução (ou via rules.json). */
  addRule(rule: PiiRule): void {
    if (rule.validator && !VALIDATORS[rule.validator]) throw new Error(`Validador desconhecido: ${rule.validator}`);
    const flags = [...new Set(((rule.flags ?? 'iu') + 'g').split(''))].join('');
    this.compiled.push({ rule, re: new RegExp(rule.pattern, flags) });
  }

  addKeyHint(hint: KeyHint): void {
    this.hints.push({ re: new RegExp(hint.pattern, 'i'), hint });
  }

  classifyKey(key: string): KeyHint | undefined {
    return this.hints.find((h) => h.re.test(key))?.hint;
  }

  get ruleCount(): number { return this.compiled.length; }

  /** Varre texto livre. Sobreposições são resolvidas por severidade > confiança > tamanho. */
  scan(text: string): Finding[] {
    const found: Finding[] = [];
    for (const { rule, re } of this.compiled) {
      for (const m of text.matchAll(re)) {
        const value = m[0];
        const start = m.index ?? 0;
        if (rule.validator && !VALIDATORS[rule.validator](value)) continue;
        if (rule.context && !this.hasContext(text, start, rule)) continue;
        found.push({
          ruleId: rule.id, label: rule.label, category: rule.category, severity: rule.severity,
          value, masked: mask(value), start, end: start + value.length,
          confidence: rule.confidence, sensitive: !!rule.sensitive,
        });
      }
    }
    return this.resolveOverlaps(found);
  }

  /** Varre objetos/JSON aninhados; também usa o NOME do campo como pista (ex.: "senha", "cpf"). */
  scanObject(data: unknown): Finding[] {
    const out: Finding[] = [];
    const visit = (v: unknown, path: string, key: string): void => {
      if (v === null || v === undefined) return;
      if (Array.isArray(v)) return v.forEach((x, i) => visit(x, `${path}[${i}]`, key));
      if (typeof v === 'object') {
        return Object.entries(v as object).forEach(([k, x]) => visit(x, path ? `${path}.${k}` : k, k));
      }
      const s = String(v);
      const content = typeof v === 'string' ? this.scan(s).map((f) => ({ ...f, path })) : [];
      out.push(...content);
      const hint = this.classifyKey(key);
      if (hint && s.length >= 3 && !content.some((f) => f.value === s)) {
        out.push({
          ruleId: `campo:${key}`, label: hint.label, category: hint.category, severity: hint.severity,
          value: s, masked: mask(s), start: 0, end: s.length, confidence: 0.9, sensitive: false, path,
        });
      }
    };
    visit(data, '', '');
    return out;
  }

  redact(text: string): string {
    let out = text;
    for (const f of this.scan(text).sort((a, b) => b.start - a.start)) {
      out = out.slice(0, f.start) + `[REDACTED:${f.ruleId}]` + out.slice(f.end);
    }
    return out;
  }

  private hasContext(text: string, start: number, rule: PiiRule): boolean {
    const before = text.slice(Math.max(0, start - (rule.contextWindow ?? 40)), start).toLowerCase();
    return rule.context!.some((c) => before.includes(c));
  }

  private resolveOverlaps(all: Finding[]): Finding[] {
    const sorted = [...all].sort((a, b) =>
      RANK[b.severity] - RANK[a.severity] || b.confidence - a.confidence || (b.end - b.start) - (a.end - a.start));
    const kept: Finding[] = [];
    for (const f of sorted) if (!kept.some((k) => f.start < k.end && k.start < f.end)) kept.push(f);
    return kept.sort((a, b) => a.start - b.start);
  }
}

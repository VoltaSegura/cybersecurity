import ts from 'typescript';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { PiiEngine } from '../pii/engine';
import type { SinkKind } from './runtime';

/** Fontes: onde dado do usuário entra. Sanitizadores: funções que "limpam" o dado. Destinos: onde ele não pode chegar. */
export const SOURCES = ['req.body', 'req.query', 'req.headers', 'req.user'];
export const SANITIZERS = new Set(['redact', 'pseudonymize', 'sanitize', 'mask', 'anonymize']);
export const SINKS: { re: RegExp; kind: SinkKind }[] = [
  { re: /^(ctx\.logger\.\w+|console\.\w+)$/, kind: 'log' },
  { re: /^ctx\.errors\.report$/, kind: 'errorReport' },
  { re: /^ctx\.analytics\.track$/, kind: 'analytics' },
  { re: /^ctx\.llm\.ask$/, kind: 'llm' },
];

const COMPARISON = new Set([
  ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken, ts.SyntaxKind.LessThanToken, ts.SyntaxKind.GreaterThanToken,
  ts.SyntaxKind.LessThanEqualsToken, ts.SyntaxKind.GreaterThanEqualsToken,
]);

export interface StaticFlow {
  file: string; line: number; sink: string; sinkKind: SinkKind;
  sources: string[]; variables: string[]; categories: string[]; snippet: string;
}

export function analyzeSource(file: string, code: string, engine: PiiEngine): StaticFlow[] {
  const sf = ts.createSourceFile(file, code, ts.ScriptTarget.ES2022, true);
  const flows: StaticFlow[] = [];

  const analyzeFunction = (fn: ts.FunctionDeclaration) => {
    const tainted = new Map<string, string>(); // variável -> origem

    // devolve as origens contaminadas presentes na expressão (vazio = limpa)
    const sourcesOf = (n: ts.Node): string[] => {
      if (ts.isCallExpression(n) && SANITIZERS.has(n.expression.getText().split('.').pop()!)) return [];
      if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) {
        const t = n.getText();
        if (SOURCES.some((s) => t === s || t.startsWith(s + '.') || t.startsWith(s + '['))) return [t];
        return sourcesOf(n.expression);
      }
      if (ts.isPropertyAssignment(n)) return sourcesOf(n.initializer);
      // expressões que só produzem boolean (condição, comparação, !, typeof) não carregam o dado adiante
      if (ts.isConditionalExpression(n)) return [...sourcesOf(n.whenTrue), ...sourcesOf(n.whenFalse)];
      if (ts.isTypeOfExpression(n)) return [];
      if (ts.isPrefixUnaryExpression(n) && n.operator === ts.SyntaxKind.ExclamationToken) return [];
      if (ts.isBinaryExpression(n) && COMPARISON.has(n.operatorToken.kind)) return [];
      if (ts.isIdentifier(n)) return tainted.has(n.text) ? [tainted.get(n.text)!] : [];
      const out: string[] = [];
      ts.forEachChild(n, (c) => { out.push(...sourcesOf(c)); }); // bloco: callback truthy interromperia a varredura
      return out;
    };

    const bind = (name: ts.BindingName, src: string) => {
      if (ts.isIdentifier(name)) return void tainted.set(name.text, src);
      for (const el of name.elements) {
        if (ts.isOmittedExpression(el)) continue;
        const field = ts.isObjectBindingPattern(name) ? (el.propertyName ?? el.name).getText() : '';
        bind(el.name, field ? `${src}.${field}` : src);
      }
    };

    // propaga contaminação por declarações e atribuições (2 passadas cobrem dependências fora de ordem)
    for (let pass = 0; pass < 2; pass++) {
      const walk = (n: ts.Node) => {
        if (ts.isVariableDeclaration(n) && n.initializer) {
          const s = sourcesOf(n.initializer);
          if (s.length) bind(n.name, s[0]);
        }
        if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left)) {
          const s = sourcesOf(n.right);
          if (s.length) tainted.set(n.left.text, s[0]);
        }
        ts.forEachChild(n, walk);
      };
      walk(fn);
    }

    // verifica cada chamada a um destino inseguro
    const check = (n: ts.Node) => {
      if (ts.isCallExpression(n)) {
        const callee = n.expression.getText();
        const sink = SINKS.find((s) => s.re.test(callee));
        if (sink) {
          const sources = n.arguments.flatMap((a) => sourcesOf(a));
          if (sources.length) {
            const vars: string[] = [];
            const ids = (x: ts.Node) => { if (ts.isIdentifier(x) && tainted.has(x.text)) vars.push(x.text); ts.forEachChild(x, ids); };
            n.arguments.forEach(ids);
            const fields = [...new Set(sources.map((s) => s.split('.').pop()!))];
            flows.push({
              file, line: sf.getLineAndCharacterOfPosition(n.getStart()).line + 1, sink: callee, sinkKind: sink.kind,
              sources: [...new Set(sources)], variables: [...new Set(vars)],
              categories: [...new Set(fields.map((f) => engine.classifyKey(f)?.category ?? 'dado-do-usuario'))],
              snippet: n.getText().split('\n')[0].slice(0, 110),
            });
          }
        }
      }
      ts.forEachChild(n, check);
    };
    check(fn);
  };

  sf.statements.filter(ts.isFunctionDeclaration).forEach(analyzeFunction);
  return flows;
}

export function analyzeDir(dir: string, engine: PiiEngine, label = dir): StaticFlow[] {
  return readdirSync(dir).filter((f) => f.endsWith('.ts'))
    .flatMap((f) => analyzeSource(`${label}/${f}`, readFileSync(join(dir, f), 'utf8'), engine));
}

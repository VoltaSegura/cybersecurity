import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { fullAudit } from '../audit/run';
import { renderDashboard } from '../dashboard/render';
import { sanitizeEvents, translateFindings, type CitizenAlert } from '../ai/remediation';
import { aiConfigured } from '../config';
import { K } from '../risk/risk';
import { c, title } from './ui';

const root = (p: string) => fileURLToPath(new URL(`../../${p}`, import.meta.url));
mkdirSync(root('auditoria'), { recursive: true });
mkdirSync(root('dashboard'), { recursive: true });

const a = fullAudit();
const findings = sanitizeEvents(a.antes.events);
const todos = await translateFindings(findings);
// um alerta por categoria (o de maior severidade)
const alertas: CitizenAlert[] = [];
for (const al of todos) if (!alertas.some((x) => x.category === al.category)) alertas.push(al);

const line = (r: typeof a.antes) => r.outputs.find((o) => o.scenario === 'consulta-de-rota' && o.sink === 'log')?.text ?? '';
const data = {
  geradoEm: new Date().toLocaleString('pt-BR'),
  risco: a.risco, estatica: a.estatica, alertas, ruleCount: a.ruleCount,
  ia: aiConfigured() ? 'llm' : 'offline', formula: { K },
  cenarios: new Set(a.antes.outputs.map((o) => o.scenario)).size,
  saidasVazadas: a.antes.outputs.filter((o) => o.status === 'vazou').length,
  evidencia: { antes: line(a.antes), bloqueio: line(a.bloqueio) },
};

// ---------- relatório de auditoria (evidências do Taint Analysis) ----------
const rows = (r: typeof a.antes) => r.outputs.map((o) =>
  `| ${o.scenario} | ${o.sink} | ${o.status} | \`${o.text.replace(/\|/g, '\\|').slice(0, 130)}\` |`).join('\n');
const md = `# Auditoria do protótipo — Taint Analysis (VoltaSegura)

> Gerado em ${data.geradoEm}. Todos os dados são **sintéticos**. Reproduza com \`npm run audit\`.

## 1. Resumo

| Execução | Vazamentos únicos | Bloqueados | Risco Cidadão |
|---|---|---|---|
| App vulnerável · monitor | ${a.risco.antes.leaks} | 0 | **${a.risco.antes.score}** (${a.risco.antes.level}) |
| App vulnerável · bloqueio em tempo real | ${a.risco.bloqueio.leaks} | ${a.risco.bloqueio.blocked} | **${a.risco.bloqueio.score}** (${a.risco.bloqueio.level}) |
| App corrigido · monitor | ${a.risco.depois.leaks} | 0 | **${a.risco.depois.score}** (${a.risco.depois.level}) |

Análise estática: **${a.estatica.antes.length}** fluxos inseguros no código vulnerável e **${a.estatica.depois.length}** no corrigido.

## 2. Método

- **Fontes (sources):** \`req.body\`, \`req.headers\`, \`req.user\`. Todo dado pessoal encontrado pelo motor de PII (${a.ruleCount} regras) é marcado na entrada, com sua origem.
- **Destinos (sinks):** log, relatório de erro, análise de uso (analytics) e LLM externo.
- **Sanitizadores:** \`redact\`, \`pseudonymize\`, \`sanitize\`, \`mask\`, \`anonymize\`.
- **Dinâmico:** o valor marcado é procurado em tudo que chega a um destino (inclusive após concatenação e template). O motor de PII também varre a saída para pegar dado não rastreado.
- **Estático:** análise da AST (compilador TypeScript) seguindo variáveis do \`req\` até chamadas de destino sem sanitizador.

## 3. Evidências — análise estática

### Código vulnerável
| Arquivo:linha | Destino | Origem do dado | Tipo |
|---|---|---|---|
${a.estatica.antes.map((f) => `| ${f.file}:${f.line} | ${f.sink} | ${f.sources.join(', ')} | ${f.categories.join(', ')} |`).join('\n')}

### Código corrigido
${a.estatica.depois.length ? a.estatica.depois.map((f) => `- ${f.file}:${f.line} ${f.sink}`).join('\n') : 'Nenhum caminho fonte → destino inseguro encontrado.'}

## 4. Evidências — execução dinâmica

### App vulnerável · monitor (o que sairia do sistema)
| Cenário | Destino | Status | Saída |
|---|---|---|---|
${rows(a.antes)}

### App vulnerável · bloqueio em tempo real
| Cenário | Destino | Status | Saída |
|---|---|---|---|
${rows(a.bloqueio)}

### App corrigido · monitor
| Cenário | Destino | Status | Saída |
|---|---|---|---|
${rows(a.depois)}

## 5. Limitações

- Cobertura de ${data.cenarios} cenários sintéticos e das regras de PII configuradas; ausência de achados não prova ausência de vazamento.
- A análise estática é intraprocedural (por função) e não segue dados entre arquivos.
- Material técnico: não afirma conformidade com a LGPD, que depende de revisão jurídica.
`;
writeFileSync(root('auditoria/taint-analysis-report.md'), md);
writeFileSync(root('auditoria/evidencias.json'), JSON.stringify({ ...data, eventos: { antes: a.antes.events, bloqueio: a.bloqueio.events, depois: a.depois.events } }, null, 2));
writeFileSync(root('dashboard/index.html'), renderDashboard(data));

title('Auditoria concluída');
console.log(`Risco Cidadão  antes ${c.red(String(a.risco.antes.score))} (${a.risco.antes.level})  →  bloqueio ${c.green(String(a.risco.bloqueio.score))}  →  corrigido ${c.green(String(a.risco.depois.score))}`);
console.log(`Fluxos estáticos  vulnerável ${a.estatica.antes.length}  ·  corrigido ${a.estatica.depois.length}\n`);
console.log('Arquivos gerados:\n  auditoria/taint-analysis-report.md\n  auditoria/evidencias.json\n  dashboard/index.html');

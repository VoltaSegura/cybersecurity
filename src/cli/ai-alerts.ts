import { runVariant } from '../audit/run';
import { sanitizeEvents, translateFindings } from '../ai/remediation';
import { AI_CONFIG, aiConfigured } from '../config';
import { c, title } from './ui';

const findings = sanitizeEvents(runVariant('vulnerable', 'monitor').events);
title(`Tradução via IA — ${aiConfigured() ? `Gemini real (${AI_CONFIG.model})` : 'modo offline (GEMINI_API_KEY não definida)'}`);
console.log(c.dim('Entrada da IA (já sem dado pessoal):'), JSON.stringify(findings[0]), '\n');
for (const a of (await translateFindings(findings.slice(0, 4)))) {
  console.log(`${c.bold(a.titulo)} ${c.dim(`[${a.severity} · ${a.sink} · fonte: ${a.fonte}]`)}`);
  console.log(`  Risco real:  ${a.riscoReal}`);
  console.log(`  O que fazer: ${a.oQueFazer}`);
  console.log(`  Correção:    ${c.cyan(a.correcaoTecnica)}\n`);
}

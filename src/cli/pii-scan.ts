import { PiiEngine } from '../pii/engine';
import { c, title, sevColor } from './ui';

const engine = new PiiEngine();
const arg = process.argv.slice(2).join(' ');
const payload = arg ? { texto: arg } : {
  usuario: { email: 'agatha.santos@example.com', senha: 'Volta@2026!' },
  chamado: 'Meu CPF é 529.982.247-25, sou diabética. Falar no (11) 98765-4321. Moro na Rua Augusta, 900.',
  trajeto: { origem: 'Av. Paulista, 1578, Bela Vista', gps: '-23.5614,-46.6559' },
  falsosPositivos: 'CPF inválido 111.111.111-11, protocolo 20261115103000, duração 1578ms',
};

title(`Motor de PII — ${engine.ruleCount} regras carregadas de rules.json`);
console.log(c.dim('Entrada:'), JSON.stringify(payload).slice(0, 160) + '…\n');
const findings = engine.scanObject(payload);
for (const f of findings) {
  console.log(`${sevColor(f.severity).padEnd(18)} ${f.label.padEnd(26)} ${f.masked.padEnd(14)} ${c.dim(f.path ?? '')}`);
}
console.log(`\n${c.bold(String(findings.length))} dados pessoais encontrados; falsos positivos ignorados (CPF inválido, protocolo, duração).`);

import { runVariant } from '../audit/run';
import { computeRisk } from '../risk/risk';
import { c, title, sevColor } from './ui';

const runs = [
  { label: 'app VULNERÁVEL — modo monitor (só detecta)', r: runVariant('vulnerable', 'monitor') },
  { label: 'app VULNERÁVEL — modo enforce (bloqueia em tempo real)', r: runVariant('vulnerable', 'enforce') },
  { label: 'app CORRIGIDO — modo monitor', r: runVariant('secure', 'monitor') },
];
for (const { label, r } of runs) {
  title(`Taint Analysis DINÂMICO — ${label}`);
  for (const o of r.outputs) {
    console.log(`${(o.status === 'vazou' ? c.red('VAZOU     ') : o.status === 'bloqueado' ? c.yellow('BLOQUEADO ') : c.green('limpo     ')) + c.dim(o.sink.padEnd(11))} ${o.text.slice(0, 120)}`);
  }
  const unique = new Set(r.events.map((e) => `${e.sink}|${e.origin}|${e.masked}`)).size;
  const risk = computeRisk(r.events);
  console.log(`\n${c.bold(String(unique))} ocorrência(s) ${r.mode === 'enforce' ? 'bloqueada(s)' : 'detectada(s)'}  →  Risco Cidadão: ${c.bold(String(risk.score))} (${risk.level})`);
  if (r.mode === 'monitor' && r.events[0]) {
    const e = r.events[0];
    console.log(c.dim(`ex.: origem ${e.origin} chegou ao destino "${e.sink}" [${sevColor(e.severity)}]`));
  }
}

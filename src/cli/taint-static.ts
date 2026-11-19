import { PiiEngine } from '../pii/engine';
import { analyzeDir } from '../taint/static';
import { APP_DIRS } from '../audit/run';
import { c, title } from './ui';

const engine = new PiiEngine();
for (const v of ['vulnerable', 'secure'] as const) {
  title(`Taint Analysis ESTÁTICO — app/${v}`);
  const flows = analyzeDir(APP_DIRS[v], engine, `app/${v}`);
  if (!flows.length) console.log(c.green('✔ nenhum caminho fonte → destino inseguro encontrado'));
  for (const f of flows) {
    console.log(`${c.red('✖')} ${f.file}:${f.line}  ${c.bold(f.sink)}  ${c.dim('←')} ${f.sources.join(', ')}  ${c.dim(`[${f.categories.join(', ')}]`)}`);
  }
  console.log(`\n${flows.length} fluxo(s) inseguro(s).`);
}

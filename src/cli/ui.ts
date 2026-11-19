const on = process.stdout.isTTY || process.env.FORCE_COLOR;
const wrap = (c: number) => (s: string) => (on ? `\x1b[${c}m${s}\x1b[0m` : s);
export const c = { red: wrap(31), green: wrap(32), yellow: wrap(33), cyan: wrap(36), dim: wrap(2), bold: wrap(1), orange: wrap(33) };
export const title = (s: string) => console.log(`\n${c.bold(c.orange('▌ ' + s))}\n`);
export const sevColor = (s: string) => (s === 'critical' ? c.red : s === 'high' ? c.orange : c.dim)(s);

const digits = (s: string) => s.replace(/\D/g, '');

export const VALIDATORS: Record<string, (v: string) => boolean> = {
  // CPF: 11 dígitos, rejeita sequências repetidas e confere os 2 dígitos verificadores
  cpf(v) {
    const d = digits(v);
    if (d.length !== 11 || /^(\d)\1{10}$/.test(d)) return false;
    const dv = (n: number) => {
      let sum = 0;
      for (let i = 0; i < n; i++) sum += Number(d[i]) * (n + 1 - i);
      const r = (sum * 10) % 11;
      return r === 10 ? 0 : r;
    };
    return dv(9) === Number(d[9]) && dv(10) === Number(d[10]);
  },
  'phone-br'(v) {
    let d = digits(v);
    if (d.startsWith('55') && d.length >= 12) d = d.slice(2);
    if (d.length !== 10 && d.length !== 11) return false;
    if (d.length === 11 && d[2] !== '9') return false;
    return Number(d.slice(0, 2)) >= 11;
  },
  coords(v) {
    const n = v.match(/-?\d+\.\d+/g)?.map(Number);
    return !!n && n.length === 2 && Math.abs(n[0]) <= 90 && Math.abs(n[1]) <= 180;
  },
  luhn(v) {
    const d = digits(v);
    if (d.length < 13 || d.length > 19) return false;
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let x = Number(d[d.length - 1 - i]);
      if (i % 2 === 1) { x *= 2; if (x > 9) x -= 9; }
      sum += x;
    }
    return sum % 10 === 0;
  },
  ipv4: (v) => v.split('.').every((o) => Number(o) <= 255),
};

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PiiEngine } from '../src/pii/engine';

const e = new PiiEngine();
const ids = (t: string) => e.scan(t).map((f) => f.ruleId);

test('CPF: formatado, sem máscara e com dígito verificador', () => {
  assert.deepEqual(ids('CPF 529.982.247-25'), ['cpf']);
  assert.deepEqual(ids('52998224725'), ['cpf']);
});
test('CPF inválido e sequências repetidas não são CPF', () => {
  assert.deepEqual(ids('111.111.111-11 e 123.456.789-00'), []);
});
test('e-mail, telefone, CEP', () => {
  assert.deepEqual(ids('a.b+c@example.com.br'), ['email']);
  assert.deepEqual(ids('(11) 98765-4321'), ['telefone-br']);
  assert.deepEqual(ids('CEP 01310-100'), ['cep']);
});
test('localização: GPS, lat/lng e endereço', () => {
  assert.deepEqual(ids('-23.5614,-46.6559'), ['gps-par']);
  assert.deepEqual(ids('lat=-23.5614 lng=-46.6559'), ['gps-campo', 'gps-campo']);
  assert.deepEqual(ids('moro na Rua Augusta, 900'), ['endereco']);
  assert.deepEqual(ids('latitude 95.1234,-46.6559'), []); // fora do intervalo válido
});
test('credenciais: senha, JWT, Bearer e chave de API', () => {
  assert.deepEqual(ids('{"senha":"Volta@2026!"}'), ['senha']);
  assert.deepEqual(ids('Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1XzhmM2EyMSJ9.c2lnbmF0dXJl'), ['bearer']);
  assert.deepEqual(ids('chave sk-abcdefghijklmnopqrstuv1234'), ['api-key']);
});
test('saúde: com e sem acento', () => {
  assert.deepEqual(ids('sou diabética'), ['saude']);
  assert.deepEqual(ids('tenho hipertensão'), ['saude']);
});
test('cartão só com Luhn válido', () => {
  assert.deepEqual(ids('4539 1488 0343 6467'), ['cartao']);
  assert.deepEqual(ids('4539 1488 0343 6468'), []);
});
test('falsos positivos: protocolo, duração, data sem contexto', () => {
  assert.deepEqual(ids('protocolo 20261115103000 em 1578ms'), []);
  assert.deepEqual(ids('12/03/2001'), []);
  assert.deepEqual(ids('nascimento 12/03/2001'), ['nascimento']);
});
test('scanObject: acha PII aninhado e usa o nome do campo', () => {
  const f = e.scanObject({ user: { senha: 'x1y2z3', tels: ['(11) 98765-4321'] } });
  assert.equal(f.find((x) => x.ruleId === 'campo:senha')?.path, 'user.senha');
  assert.equal(f.find((x) => x.ruleId === 'telefone-br')?.path, 'user.tels[0]');
});
test('redact troca o dado por etiqueta', () => {
  assert.equal(e.redact('cpf 529.982.247-25 ok'), 'cpf [REDACTED:cpf] ok');
});
test('nova regra pode ser adicionada sem alterar o código do motor', () => {
  const eng = new PiiEngine();
  eng.addRule({ id: 'matricula', label: 'Matrícula FIAP', category: 'identificador', severity: 'medium', pattern: 'RM\\d{6}', confidence: 0.9 });
  assert.deepEqual(eng.scan('aluno RM551234').map((f) => f.ruleId), ['matricula']);
});

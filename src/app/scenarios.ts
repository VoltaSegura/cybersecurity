import type { Scenario } from '../taint/runtime';
import type { Req } from './types';

// Dados 100% sintéticos (CPF de exemplo com dígito válido, e-mail @example.com).
const usuario = { id: 'u_8f3a21', email: 'agatha.santos@example.com' };
const rota = {
  origem: 'Av. Paulista, 1578, Bela Vista',
  destino: 'Rua Vergueiro, 3185, Vila Mariana',
  lat: -23.5614, lng: -46.6559, horario: '22:40',
};
const req = (body: Req['body'], headers: Req['headers'] = {}): Req => ({ body, headers, user: usuario });

export const SCENARIOS: Scenario[] = [
  { name: 'consulta-de-rota', handler: 'consultarRota', req: req(rota) },
  { name: 'consulta-com-falha', handler: 'consultarRota', req: req({ ...rota, horario: '' }) },
  {
    name: 'login', handler: 'login',
    req: req({ email: usuario.email, senha: 'Volta@2026!' },
      { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1XzhmM2EyMSJ9.c2lnbmF0dXJlLWZpY3RpY2lh' }),
  },
  {
    name: 'chamado-de-suporte', handler: 'abrirChamado',
    req: req({ texto: 'Meu CPF é 529.982.247-25, sou diabética e preciso de ajuda. Contato: (11) 98765-4321. Moro na Rua Augusta, 900.' }),
  },
  { name: 'compartilhar-trajeto', handler: 'compartilharTrajeto', req: req({ lat: -23.5505, lng: -46.6333 }) },
];

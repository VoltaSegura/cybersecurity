import type { Req, Ctx } from '../types';

// VERSÃO CORRIGIDA: logs só com eventos e métricas; qualquer texto do usuário passa por sanitizador.

export function consultarRota(req: Req, ctx: Ctx) {
  const { origem, destino, lat, lng, horario } = req.body;
  const inicio = Date.now();
  const opcoes = origem && destino && lat && lng ? 2 : 0; // dados usados só para calcular a resposta

  if (!horario) {
    ctx.errors.report('falha_calculo_rota codigo=E_HORARIO_AUSENTE');
    return { ok: false };
  }
  ctx.logger.info({ evento: 'rota_consultada', duracaoMs: Date.now() - inicio, opcoes });
  ctx.analytics.track('rota_consultada', { opcoes });
  return { ok: true, opcoes };
}

export function login(req: Req, ctx: Ctx) {
  const { email } = req.body;
  ctx.logger.info(`login_tentativa usuario=${ctx.privacy.pseudonymize(String(email))}`);
  return { ok: true };
}

export function abrirChamado(req: Req, ctx: Ctx) {
  const { texto } = req.body;
  const resumo = ctx.llm.ask(`Resuma o chamado do usuário: ${ctx.privacy.redact(String(texto))}`);
  return { ok: true, resumo };
}

export function compartilharTrajeto(req: Req, ctx: Ctx) {
  const { lat, lng } = req.body;
  const valido = typeof lat === 'number' && typeof lng === 'number';
  ctx.logger.info({ evento: 'compartilhamento_atualizado', valido });
  return { ok: valido };
}

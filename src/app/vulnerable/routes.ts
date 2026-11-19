import type { Req, Ctx } from '../types';

// VERSÃO VULNERÁVEL: reproduz erros comuns que quebram as regras de privacidade do VoltaSegura
// (logs sem coordenadas, consultas descartadas, nada de dado pessoal em serviço externo).

export function consultarRota(req: Req, ctx: Ctx) {
  const { origem, destino, lat, lng, horario } = req.body;
  const email = req.user?.email;

  // vazamento: origem/destino/GPS/e-mail em log, vinculados à conta
  ctx.logger.info(`consulta de rota ${origem} -> ${destino} (${lat},${lng}) por ${email}`);
  ctx.analytics.track('rota_consultada', { origem, destino, usuario: email });

  if (!horario) {
    // vazamento: corpo inteiro da requisição vai para o relatório de erros
    ctx.errors.report(`falha ao calcular rota: ${JSON.stringify(req.body)}`);
    return { ok: false };
  }
  return { ok: true, opcoes: 2 };
}

export function login(req: Req, ctx: Ctx) {
  const { email, senha } = req.body;
  const token = req.headers.authorization;
  ctx.logger.debug(`tentativa de login ${email} senha=${senha}`); // vazamento: senha em log
  ctx.logger.info(`sessão iniciada com ${token}`);                // vazamento: token em log
  return { ok: true };
}

export function abrirChamado(req: Req, ctx: Ctx) {
  const { texto } = req.body;
  // vazamento: texto livre (CPF, saúde, telefone, endereço) enviado a um LLM externo
  const resumo = ctx.llm.ask(`Resuma o chamado do usuário: ${texto}`);
  return { ok: true, resumo };
}

export function compartilharTrajeto(req: Req, ctx: Ctx) {
  const { lat, lng } = req.body;
  ctx.logger.info(`posição ao vivo da sessão: ${lat},${lng}`); // vazamento: posição ao vivo em log
  return { ok: true };
}

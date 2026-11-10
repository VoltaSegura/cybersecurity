# cybersecurity — entrega da disciplina Cybersecurity (VoltaSegura)

> 🗂 **Ficha da CitizenTech** — resumo do produto **VoltaSegura** (ex-"CitizenTech"; renomeado em 10/11/2026):
> cidade São Paulo; cidadão = estudante universitário do período noturno;
> problema = falta de visão integrada das condições urbanas que influenciam a percepção de segurança no deslocamento;
> como funciona = comparação de alternativas de ida/volta com exposição estimada e confiança dos dados;
> ODS = 11 e 10. Ficha completa: monorepo **https://github.com/VoltaSegura/voltasegura**.
> ⚠️ O produto não garante segurança e não classifica bairros — comunicar apenas exposição estimada e confiança dos dados (=`docs`/04).

**Monorepo central (fonte da verdade)**: https://github.com/VoltaSegura/voltasegura

# VoltaSegura — Cybersecurity

Módulo de segurança do VoltaSegura: regras de tratamento de **PII** (dados de localização), evidências de **Taint Analysis** e dashboard do indicador **Risco Cidadão**.

> ⚠️ Em construção. Alinhado aos princípios de [`docs/03_projeto_documento_vivo.md`](../../docs/03_projeto_documento_vivo.md) (seção Ética/privacidade) e à LGPD (Lei nº 13.709/2018).
>
> Entrega em ZIP: (1) código do módulo com regras PII; (2) evidências de Taint Analysis; (3) vídeo + print do dashboard gerando o indicador.

## Principais (do documento vivo)

- Privacidade desde a concepção e minimização de dados;
- Não vender histórico individual de localização;
- Relatórios institucionais apenas agregados e anonimizados.

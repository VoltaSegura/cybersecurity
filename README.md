# VoltaSegura — Módulo de Cybersecurity

Módulo em **Node + TypeScript** que protege os dados pessoais de quem usa o VoltaSegura: reconhece PII, rastreia o caminho desses dados (Taint Analysis), traduz achados técnicos em alertas de risco real e calcula o indicador **Risco Cidadão**.

> Os dados usados nas demonstrações são **sintéticos**. O módulo apoia os princípios de minimização e privacidade desde a concepção do projeto; ele **não** atesta conformidade com a LGPD, que depende de revisão jurídica.

## Integrantes

| RM | Nome completo |
|---|---|
| 565065 | Augusto Barcelos Barros |
| 556197 | Caio Felipe de Lima Bezerra |
| 555541 | Juan Francisco Alves Muradas |
| 555931 | Lucas Derenze Simidu |
| 554873 | Sofia Fernandes |

## Requisitos
- Node.js 20.12 ou superior (testado no 22)

```bash
npm install
```

## ⚠️ Campos que você precisa preencher

Copie `.env.example` para `.env` e preencha:

```bash
cp .env.example .env
```

| Campo no `.env` | Obrigatório? | O que colocar |
|---|---|---|
| **`GEMINI_API_KEY`** | **SIM — PREENCHER** | Sua chave da API do Gemini. Crie em https://aistudio.google.com/apikey (Google AI Studio → *Create API key*). Há plano gratuito, com limite de requisições por minuto. |
| `GEMINI_MODEL` | Não (padrão: `gemini-3.5-flash-lite`) | Os nomes de modelo mudam com frequência. Se der erro 404, rode `npm run ai:models` e copie um nome da lista. |
| `GEMINI_API_URL` | Não (padrão: `https://generativelanguage.googleapis.com/v1beta`) | Só mude se usar outro endpoint compatível. |

Depois de salvar o `.env`, rode `npm run ai:alerts`: o título deve mostrar **"Gemini real (modelo)"** e cada alerta `fonte: llm`. Rode `npm run audit` de novo para regenerar o dashboard com os alertas escritos pelo Gemini.

> Nunca envie o `.env` na entrega: ele já está no `.gitignore` e **fora do ZIP**.

## Comandos

| Comando | O que faz |
|---|---|
| `npm run pii:scan` | Mostra o motor de PII varrendo um payload de exemplo (ou um texto: `npm run pii:scan -- "texto"`) |
| `npm test` | Executa os 22 testes automatizados |
| `npm run taint:static` | Taint Analysis estático (AST) no app vulnerável e no corrigido |
| `npm run taint:runtime` | Taint Analysis dinâmico: monitor, bloqueio em tempo real e app corrigido |
| `npm run ai:alerts` | Traduz achados técnicos em alertas para o cidadão |
| `npm run ai:models` | Lista os modelos Gemini que a sua chave pode usar |
| `npm run audit` | Roda tudo e gera `auditoria/` e `dashboard/index.html` |
| `npm run typecheck` | Verificação de tipos |

## Estrutura

```
src/pii/          motor de PII (engine, validadores) e rules.json com as regras
src/taint/        Taint Analysis: runtime.ts (dinâmico) e static.ts (AST)
src/app/          backend simulado do VoltaSegura: vulnerable/ e secure/, mais cenários
src/ai/           tradução de achados em alertas (LLM ou modo offline)
src/risk/         cálculo do indicador Risco Cidadão
src/dashboard/    gerador do dashboard HTML
src/cli/          comandos npm
tests/            testes automatizados
auditoria/        relatório e evidências geradas pelo Taint Analysis
dashboard/        index.html gerado
```

## Motor de PII

Regras ficam em `src/pii/rules.json` (15 regras e 7 pistas por nome de campo). Cobre CPF (com dígito verificador), e-mail, telefone, CEP, coordenadas GPS, endereço, senha, JWT/Bearer, chaves de API, cartão (Luhn), data de nascimento, IP e termos de saúde.

Para criar uma regra, adicione um item ao JSON ou chame `engine.addRule({...})`:

```json
{ "id": "matricula", "label": "Matrícula FIAP", "category": "identificador", "severity": "medium", "pattern": "RM\\d{6}", "confidence": 0.9 }
```

Campos opcionais: `validator` (função em `validators.ts`), `context` e `contextWindow` (palavra que precisa aparecer antes do match) e `sensitive`.

## Taint Analysis

- **Fontes:** `req.body`, `req.headers`, `req.user`.
- **Destinos:** log, relatório de erro, analytics e LLM externo.
- **Sanitizadores:** `redact`, `pseudonymize`, `sanitize`, `mask`, `anonymize`.
- **Dinâmico:** marca na entrada todo dado pessoal e detecta se ele chega a um destino inseguro, mesmo após concatenação. No modo `enforce`, mascara antes de sair.
- **Estático:** segue variáveis do `req` até as chamadas de destino, usando a AST do TypeScript.

## Risco Cidadão

Vai de 0 a 100 e mede o risco aos **dados pessoais** do usuário, nunca o risco de um território. Cada vazamento único pesa `severidade × exposição do destino` (×1,25 para dado de saúde): `score = 100 × (1 − e^(−soma/40))`. Níveis: Baixo (<25), Moderado, Alto e Crítico (≥75).

## IA (Gemini)

A camada de IA chama a **API do Gemini** (`generateContent`) **uma única vez** com todos os achados, para escrever os alertas ao cidadão (isso poupa a cota do plano gratuito). Ela recebe apenas achados **sem dado pessoal** (categoria, destino, severidade e contagem) e tem uma guarda de saída que bloqueia qualquer prompt com PII antes do envio. Se a chave não estiver definida, ou se a chamada falhar, o módulo usa o modo offline e avisa no terminal; nesse caso, o alerta aparece com `fonte: offline`. Em caso de erro 429 (limite do plano gratuito), ele tenta de novo automaticamente.

Código em `src/ai/remediation.ts`; configuração em `src/config.ts`.

## Limitações
- A análise estática é por função (não segue dados entre arquivos).
- Cobertura limitada aos 5 cenários sintéticos e às regras configuradas: zero achados não prova ausência de vazamento.
- O backend em `src/app/` é uma simulação criada para demonstrar o módulo, não o código real do VoltaSegura.

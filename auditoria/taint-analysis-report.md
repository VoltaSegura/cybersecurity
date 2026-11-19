# Auditoria do protótipo — Taint Analysis (VoltaSegura)

> Gerado em 19/11/2026, 16:05:33. Todos os dados são **sintéticos**. Reproduza com `npm run audit`.

## 1. Resumo

| Execução | Vazamentos únicos | Bloqueados | Risco Cidadão |
|---|---|---|---|
| App vulnerável · monitor | 26 | 0 | **95** (Crítico) |
| App vulnerável · bloqueio em tempo real | 0 | 26 | **0** (Baixo) |
| App corrigido · monitor | 0 | 0 | **0** (Baixo) |

Análise estática: **7** fluxos inseguros no código vulnerável e **0** no corrigido.

## 2. Método

- **Fontes (sources):** `req.body`, `req.headers`, `req.user`. Todo dado pessoal encontrado pelo motor de PII (15 regras) é marcado na entrada, com sua origem.
- **Destinos (sinks):** log, relatório de erro, análise de uso (analytics) e LLM externo.
- **Sanitizadores:** `redact`, `pseudonymize`, `sanitize`, `mask`, `anonymize`.
- **Dinâmico:** o valor marcado é procurado em tudo que chega a um destino (inclusive após concatenação e template). O motor de PII também varre a saída para pegar dado não rastreado.
- **Estático:** análise da AST (compilador TypeScript) seguindo variáveis do `req` até chamadas de destino sem sanitizador.

## 3. Evidências — análise estática

### Código vulnerável
| Arquivo:linha | Destino | Origem do dado | Tipo |
|---|---|---|---|
| app/vulnerable/routes.ts:11 | ctx.logger.info | req.body.origem, req.body.destino, req.body.lat, req.body.lng, req.user | localizacao, dado-do-usuario |
| app/vulnerable/routes.ts:12 | ctx.analytics.track | req.body.origem, req.body.destino, req.user | localizacao, dado-do-usuario |
| app/vulnerable/routes.ts:16 | ctx.errors.report | req.body | dado-do-usuario |
| app/vulnerable/routes.ts:25 | ctx.logger.debug | req.body.email, req.body.senha | contato, credencial |
| app/vulnerable/routes.ts:26 | ctx.logger.info | req.headers.authorization | credencial |
| app/vulnerable/routes.ts:33 | ctx.llm.ask | req.body.texto | dado-do-usuario |
| app/vulnerable/routes.ts:39 | ctx.logger.info | req.body.lat, req.body.lng | localizacao |

### Código corrigido
Nenhum caminho fonte → destino inseguro encontrado.

## 4. Evidências — execução dinâmica

### App vulnerável · monitor (o que sairia do sistema)
| Cenário | Destino | Status | Saída |
|---|---|---|---|
| consulta-de-rota | log | vazou | `consulta de rota Av. Paulista, 1578, Bela Vista -> Rua Vergueiro, 3185, Vila Mariana (-23.5614,-46.6559) por agatha.santos@example` |
| consulta-de-rota | analytics | vazou | `{"name":"rota_consultada","props":{"origem":"Av. Paulista, 1578, Bela Vista","destino":"Rua Vergueiro, 3185, Vila Mariana","usuari` |
| consulta-com-falha | log | vazou | `consulta de rota Av. Paulista, 1578, Bela Vista -> Rua Vergueiro, 3185, Vila Mariana (-23.5614,-46.6559) por agatha.santos@example` |
| consulta-com-falha | analytics | vazou | `{"name":"rota_consultada","props":{"origem":"Av. Paulista, 1578, Bela Vista","destino":"Rua Vergueiro, 3185, Vila Mariana","usuari` |
| consulta-com-falha | errorReport | vazou | `falha ao calcular rota: {"origem":"Av. Paulista, 1578, Bela Vista","destino":"Rua Vergueiro, 3185, Vila Mariana","lat":-23.5614,"l` |
| login | log | vazou | `tentativa de login agatha.santos@example.com senha=Volta@2026!` |
| login | log | vazou | `sessão iniciada com Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1XzhmM2EyMSJ9.c2lnbmF0dXJlLWZpY3RpY2lh` |
| chamado-de-suporte | llm | vazou | `Resuma o chamado do usuário: Meu CPF é 529.982.247-25, sou diabética e preciso de ajuda. Contato: (11) 98765-4321. Moro na Rua Aug` |
| compartilhar-trajeto | log | vazou | `posição ao vivo da sessão: -23.5505,-46.6333` |

### App vulnerável · bloqueio em tempo real
| Cenário | Destino | Status | Saída |
|---|---|---|---|
| consulta-de-rota | log | bloqueado | `consulta de rota [BLOQUEADO:req.body.origem] -> [BLOQUEADO:req.body.destino] ([BLOQUEADO:req.body.lat],[BLOQUEADO:req.body.lng]) p` |
| consulta-de-rota | analytics | bloqueado | `{"name":"rota_consultada","props":{"origem":"[BLOQUEADO:req.body.origem]","destino":"[BLOQUEADO:req.body.destino]","usuario":"[BLO` |
| consulta-com-falha | log | bloqueado | `consulta de rota [BLOQUEADO:req.body.origem] -> [BLOQUEADO:req.body.destino] ([BLOQUEADO:req.body.lat],[BLOQUEADO:req.body.lng]) p` |
| consulta-com-falha | analytics | bloqueado | `{"name":"rota_consultada","props":{"origem":"[BLOQUEADO:req.body.origem]","destino":"[BLOQUEADO:req.body.destino]","usuario":"[BLO` |
| consulta-com-falha | errorReport | bloqueado | `falha ao calcular rota: {"origem":"[BLOQUEADO:req.body.origem]","destino":"[BLOQUEADO:req.body.destino]","lat":[BLOQUEADO:req.body` |
| login | log | bloqueado | `tentativa de login [BLOQUEADO:req.user.email] [REDACTED:senha]` |
| login | log | bloqueado | `sessão iniciada com [BLOQUEADO:req.headers.authorization]` |
| chamado-de-suporte | llm | bloqueado | `Resuma o chamado do usuário: Meu CPF é [BLOQUEADO:req.body.texto], sou [BLOQUEADO:req.body.texto] e preciso de ajuda. Contato: [BL` |
| compartilhar-trajeto | log | bloqueado | `posição ao vivo da sessão: [BLOQUEADO:req.body.lat],[BLOQUEADO:req.body.lng]` |

### App corrigido · monitor
| Cenário | Destino | Status | Saída |
|---|---|---|---|
| consulta-de-rota | log | limpo | `{"evento":"rota_consultada","duracaoMs":0,"opcoes":2}` |
| consulta-de-rota | analytics | limpo | `{"name":"rota_consultada","props":{"opcoes":2}}` |
| consulta-com-falha | errorReport | limpo | `falha_calculo_rota codigo=E_HORARIO_AUSENTE` |
| login | log | limpo | `login_tentativa usuario=anon_835c0dbd` |
| chamado-de-suporte | llm | limpo | `Resuma o chamado do usuário: Meu CPF é [BLOQUEADO:req.body.texto], sou [BLOQUEADO:req.body.texto] e preciso de ajuda. Contato: [BL` |
| compartilhar-trajeto | log | limpo | `{"evento":"compartilhamento_atualizado","valido":true}` |

## 5. Limitações

- Cobertura de 5 cenários sintéticos e das regras de PII configuradas; ausência de achados não prova ausência de vazamento.
- A análise estática é intraprocedural (por função) e não segue dados entre arquivos.
- Material técnico: não afirma conformidade com a LGPD, que depende de revisão jurídica.

import { AI_CONFIG, aiConfigured } from '../config';
import { c, title } from './ui';

// Lista os modelos Gemini que a SUA chave pode usar (os nomes mudam com frequência).
title('Modelos Gemini disponíveis para a sua chave');
if (!aiConfigured()) {
  console.log('Defina GEMINI_API_KEY no arquivo .env e rode novamente.');
  process.exit(1);
}
const res = await fetch(`${AI_CONFIG.baseUrl}/models?pageSize=200`, { headers: { 'x-goog-api-key': AI_CONFIG.apiKey } });
if (!res.ok) {
  console.log(c.red(`Erro ${res.status}: ${(await res.text()).slice(0, 300)}`));
  process.exit(1);
}
const { models = [] } = (await res.json()) as { models?: { name: string; supportedGenerationMethods?: string[] }[] };
const ids = models.filter((m) => m.supportedGenerationMethods?.includes('generateContent') && /gemini/.test(m.name)).map((m) => m.name.replace('models/', ''));
ids.forEach((id) => console.log(`${id === AI_CONFIG.model ? c.green('● ') : '  '}${id}`));
console.log(`\nModelo em uso: ${c.bold(AI_CONFIG.model)} ${ids.includes(AI_CONFIG.model) ? c.green('(disponível)') : c.red('(NÃO está na lista: ajuste GEMINI_MODEL no .env)')}`);

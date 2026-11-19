import { existsSync } from 'node:fs';

// Carrega o arquivo .env (se existir) sem dependências externas (Node 20.12+)
if (existsSync('.env')) {
  try { process.loadEnvFile('.env'); } catch { /* .env inválido: segue com as variáveis do ambiente */ }
}

export interface AiConfig { baseUrl: string; apiKey: string; model: string }

/** API do Gemini (Google AI Studio). Só GEMINI_API_KEY é obrigatória; o restante tem padrão. */
export const AI_CONFIG: AiConfig = {
  baseUrl: (process.env.GEMINI_API_URL || 'https://generativelanguage.googleapis.com/v1beta').replace(/\/$/, ''),
  apiKey: process.env.GEMINI_API_KEY || '',
  model: process.env.GEMINI_MODEL || 'gemini-3.5-flash-lite',
};

export const aiConfigured = (c: AiConfig = AI_CONFIG): boolean => c.apiKey.trim().length > 0 && !c.apiKey.includes('PLACEHOLDER');

/** Contrato mínimo do backend simulado do VoltaSegura. */
export interface Req {
  body: Record<string, unknown>;
  headers: Record<string, string>;
  user?: { id: string; email: string };
}

export interface Ctx {
  logger: { info(...a: unknown[]): void; debug(...a: unknown[]): void; error(...a: unknown[]): void };
  errors: { report(...a: unknown[]): void };
  analytics: { track(event: string, props?: Record<string, unknown>): void };
  llm: { ask(prompt: string): string };
  privacy: { redact(text: string): string; pseudonymize(value: string): string };
}

export type Handler = (req: Req, ctx: Ctx) => unknown;

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Category = 'identificador' | 'contato' | 'localizacao' | 'credencial' | 'saude' | 'financeiro' | 'rede';

export interface PiiRule {
  id: string;
  label: string;
  category: Category;
  severity: Severity;
  pattern: string;
  flags?: string;
  validator?: string;       // nome de um validador em validators.ts (ex.: dígito verificador do CPF)
  context?: string[];       // palavras que precisam aparecer antes do match
  contextWindow?: number;
  confidence: number;
  sensitive?: boolean;      // dado sensível pela LGPD (ex.: saúde)
}

export interface KeyHint { pattern: string; category: Category; severity: Severity; label: string }
export interface RuleSet { rules: PiiRule[]; keyHints: KeyHint[] }

export interface Finding {
  ruleId: string;
  label: string;
  category: Category;
  severity: Severity;
  value: string;
  masked: string;
  start: number;
  end: number;
  confidence: number;
  sensitive: boolean;
  path?: string;
}

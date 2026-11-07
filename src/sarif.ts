/**
 * SARIF to taxonomy identifiers. Only identifiers leave the runner: CWE, CVE/GHSA
 * flag and the tool name. Never paths, messages, snippets or fingerprints.
 */

export const MAX_FINDINGS = 200;
export const MAX_IDENTIFIERS_PER_LIST = 10;
export const MAX_IDENTIFIER_LENGTH = 120;
const MAX_TOOL_NAME_LENGTH = 200;

export interface ActionFinding {
  toolName: string | null;
  cwe: string[];
  cveOrGhsa: boolean;
  /** OWASP Top 10 2021 categories (`A10:2021`). Sonar only; the backend uses a few when no CWE matches. */
  owaspTop10?: string[];
}

export class SarifError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SarifError';
  }
}

/** Driver names (lower-cased) the backend treats as secret scanners. */
const SECRETS_TOOLS = new Set(['gitleaks', 'trufflehog', 'github secret scanning']);

/**
 * Leading part only. Semgrep sends `CWE-704: Incorrect Type Conversion`; the
 * backend normalizer reads just the prefix, so the title is cut to keep each identifier under the length limit.
 */
const CWE_TAG = /^(?:external\/cwe\/cwe-|cwe-)\d{1,7}(?!\d)/i;
/** An advisory id as the whole value or as the `_`-separated tail, e.g. Azure DevOps `DEP1001_GHSA-68w8-qjq3-2gfm`. */
const CVE_OR_GHSA = /(?:^|_)(?:CVE-\d{4}-\d{4,}|GHSA(?:-[a-z0-9]{4}){3})$/i;

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
/** With a baseline, only what this run added or changed counts. `unchanged` and `absent` are pre-existing or gone. */
const BASELINE_COUNTED = new Set(['new', 'updated']);
const asString = (v: unknown): string | null => (typeof v === 'string' && v.trim() !== '' ? v.trim() : null);

interface RuleInfo {
  tags: string[];
}

function tagsOf(rule: unknown): string[] {
  if (!isObject(rule) || !isObject(rule.properties)) return [];
  return asArray(rule.properties.tags).filter((t): t is string => typeof t === 'string');
}

/** CodeQL can place rules under `tool.extensions[].rules`, so index those too. */
function indexRules(tool: Json): { byId: Map<string, RuleInfo>; byIndex: RuleInfo[] } {
  const byId = new Map<string, RuleInfo>();
  const byIndex: RuleInfo[] = [];
  const driver = isObject(tool.driver) ? tool.driver : {};
  asArray(driver.rules).forEach((rule, i) => {
    const info = { tags: tagsOf(rule) };
    byIndex[i] = info;
    const id = isObject(rule) ? asString(rule.id) : null;
    if (id) byId.set(id, info);
  });
  for (const ext of asArray(tool.extensions)) {
    if (!isObject(ext)) continue;
    for (const rule of asArray(ext.rules)) {
      const id = isObject(rule) ? asString(rule.id) : null;
      if (id && !byId.has(id)) byId.set(id, { tags: tagsOf(rule) });
    }
  }
  return { byId, byIndex };
}

function pick(tags: string[], pattern: RegExp): string[] {
  const out: string[] = [];
  for (const tag of tags) {
    const m = pattern.exec(tag.trim());
    if (!m) continue;
    const id = m[0];
    if (id.length > MAX_IDENTIFIER_LENGTH) continue;
    if (!out.some((o) => o.toLowerCase() === id.toLowerCase())) out.push(id);
    if (out.length === MAX_IDENTIFIERS_PER_LIST) break;
  }
  return out;
}

function parse(sarif: unknown): unknown {
  if (typeof sarif !== 'string') return sarif;
  try {
    return JSON.parse(sarif);
  } catch {
    throw new SarifError('SARIF file is not valid JSON');
  }
}

export function extractFindings(sarif: unknown): ActionFinding[] {
  const doc = parse(sarif);
  if (!isObject(doc) || !Array.isArray(doc.runs)) {
    throw new SarifError('SARIF file has no runs array');
  }
  const unique = new Map<string, ActionFinding>();
  for (const run of doc.runs) {
    if (!isObject(run) || !isObject(run.tool)) continue;
    const driver = isObject(run.tool.driver) ? run.tool.driver : {};
    const rawName = asString(driver.name);
    const toolName = rawName ? rawName.slice(0, MAX_TOOL_NAME_LENGTH) : null;
    const isSecrets = rawName !== null && SECRETS_TOOLS.has(rawName.toLowerCase());
    const rules = indexRules(run.tool);

    // Only rules that produced a result count, never the whole ruleset.
    for (const result of asArray(run.results)) {
      if (!isObject(result)) continue;
      if (result.baselineState !== undefined && !BASELINE_COUNTED.has(String(result.baselineState))) continue;
      // `pass`, `open`, `review`, `notApplicable` and `informational` aren't findings, and a suppressed result was dismissed.
      if (result.kind !== undefined && result.kind !== 'fail') continue;
      if (asArray(result.suppressions).length > 0) continue;
      const ref = isObject(result.rule) ? result.rule : {};
      const ruleId = asString(result.ruleId) ?? asString(ref.id);
      let info = ruleId ? rules.byId.get(ruleId) : undefined;
      if (!info) {
        const index = typeof result.ruleIndex === 'number' ? result.ruleIndex : ref.index;
        if (typeof index === 'number') info = rules.byIndex[index];
      }
      const tags = info?.tags ?? [];
      const finding: ActionFinding = {
        toolName,
        cwe: pick(tags, CWE_TAG),
        cveOrGhsa: (ruleId !== null && CVE_OR_GHSA.test(ruleId)) || tags.some((t) => CVE_OR_GHSA.test(t.trim())),
      };
      if (!isSecrets && !finding.cveOrGhsa && finding.cwe.length === 0) continue;
      const key = JSON.stringify([finding.toolName, finding.cwe, finding.cveOrGhsa]);
      if (!unique.has(key)) unique.set(key, finding);
    }
  }
  return [...unique.values()].slice(0, MAX_FINDINGS);
}

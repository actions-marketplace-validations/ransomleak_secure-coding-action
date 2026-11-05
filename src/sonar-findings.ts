import type { ActionFinding } from './sarif.ts';
import type { SonarHotspot, SonarIssue } from './sonar-client.ts';
import { MAX_FINDINGS, MAX_IDENTIFIERS_PER_LIST } from './sarif.ts';

/**
 * Sonar issues and hotspots to the same finding shape `sarif.ts` produces.
 * Only identifiers leave the runner: CWE ids, OWASP Top 10 2021 categories and the scanner name.
 * Never paths, messages or rule text.
 */

export const SONAR_TOOL_NAME = 'SonarQube';

/** `cwe:89` from `securityStandards`, or a `cwe-89` / `cwe:89` issue tag. A bare `cwe` tag names no id. */
const CWE_STANDARD = /^cwe[:-](\d{1,7})$/i;
/** `owaspTop10-2021:a3`. The 2017 edition (`owaspTop10:a1`) numbers categories differently and is not sent. */
const OWASP_2021_STANDARD = /^owaspTop10-2021:a(\d{1,2})$/i;
const REPORTED_PROBABILITY = new Set(['HIGH', 'MEDIUM']);

const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strings = (v: unknown): string[] => asArray(v).filter((s): s is string => typeof s === 'string');

function cweFrom(values: string[]): string[] {
  const out: string[] = [];
  for (const v of values) {
    const m = CWE_STANDARD.exec(v.trim());
    if (!m) continue;
    const id = `CWE-${parseInt(m[1], 10)}`;
    if (!out.includes(id)) out.push(id);
    if (out.length === MAX_IDENTIFIERS_PER_LIST) break;
  }
  return out;
}

function owaspFrom(values: string[]): string[] {
  const out: string[] = [];
  for (const v of values) {
    const m = OWASP_2021_STANDARD.exec(v.trim());
    if (!m) continue;
    const id = `A${parseInt(m[1], 10)}:2021`;
    if (!out.includes(id)) out.push(id);
    if (out.length === MAX_IDENTIFIERS_PER_LIST) break;
  }
  return out;
}

/** OWASP is added only when present, so CWE-only findings keep the original payload shape. */
function toFinding(standards: string[]): ActionFinding | null {
  const cwe = cweFrom(standards);
  const owasp = owaspFrom(standards);
  if (cwe.length === 0 && owasp.length === 0) return null;
  const finding: ActionFinding = { toolName: SONAR_TOOL_NAME, cwe, cveOrGhsa: false };
  if (owasp.length > 0) finding.owaspTop10 = owasp;
  return finding;
}

/** Older servers send only `type`, newer ones also (or only) `impacts` with `softwareQuality: SECURITY`. */
export function isSecurityIssue(issue: SonarIssue): boolean {
  if (issue.type === 'VULNERABILITY') return true;
  if (typeof issue.type === 'string') return false;
  return asArray(issue.impacts).some(
    (i) => typeof i === 'object' && i !== null && (i as { softwareQuality?: unknown }).softwareQuality === 'SECURITY',
  );
}

export function issueToFinding(issue: SonarIssue, ruleStandards: Map<string, string[]>): ActionFinding | null {
  if (!isSecurityIssue(issue)) return null;
  const rule = typeof issue.rule === 'string' ? issue.rule : null;
  const standards = rule ? ruleStandards.get(rule) : undefined;
  return toFinding(standards ?? strings(issue.tags));
}

/** Only hotspots Sonar rates HIGH or MEDIUM probability. */
export function hotspotToFinding(hotspot: SonarHotspot, ruleStandards: Map<string, string[]>): ActionFinding | null {
  if (typeof hotspot.vulnerabilityProbability !== 'string') return null;
  if (!REPORTED_PROBABILITY.has(hotspot.vulnerabilityProbability.toUpperCase())) return null;
  if (hotspot.status !== undefined && hotspot.status !== 'TO_REVIEW') return null;
  const rule = typeof hotspot.ruleKey === 'string' ? hotspot.ruleKey : null;
  return toFinding((rule && ruleStandards.get(rule)) || []);
}

/** Rule keys whose standards are needed. */
export function ruleKeysOf(issues: SonarIssue[], hotspots: SonarHotspot[]): string[] {
  const keys = new Set<string>();
  for (const i of issues) if (isSecurityIssue(i) && typeof i.rule === 'string') keys.add(i.rule);
  for (const h of hotspots) if (typeof h.ruleKey === 'string') keys.add(h.ruleKey);
  return [...keys];
}

/** Deduped by identifier set and capped, like `extractFindings`. */
export function sonarFindings(
  issues: SonarIssue[],
  hotspots: SonarHotspot[],
  ruleStandards: Map<string, string[]>,
): ActionFinding[] {
  const unique = new Map<string, ActionFinding>();
  const add = (f: ActionFinding | null) => {
    if (!f) return;
    const key = JSON.stringify([f.cwe, f.owaspTop10 ?? []]);
    if (!unique.has(key)) unique.set(key, f);
  };
  for (const i of issues) add(issueToFinding(i, ruleStandards));
  for (const h of hotspots) add(hotspotToFinding(h, ruleStandards));
  return [...unique.values()].slice(0, MAX_FINDINGS);
}

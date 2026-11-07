/**
 * Reads a pull request's security findings from SonarQube Server or SonarQube Cloud.
 * The token is only ever sent to the configured Sonar host. Nothing here logs it.
 */

export const SONAR_PAGE_SIZE = 500;
export const SONAR_MAX_ISSUES = 2000;
const REQUEST_TIMEOUT_MS = 10_000;
const POLL_INTERVAL_MS = 3_000;

export type SonarErrorKind = 'auth' | 'no-pr' | 'timeout' | 'mismatch' | 'stale' | 'failed' | 'http';

export class SonarError extends Error {
  readonly kind: SonarErrorKind;
  readonly status?: number;

  constructor(kind: SonarErrorKind, message: string, status?: number) {
    super(message);
    this.name = 'SonarError';
    this.kind = kind;
    this.status = status;
  }
}

export interface SonarConfig {
  hostUrl: string;
  /** Empty for anonymous reads of public projects. */
  token: string;
  projectKey: string;
  organization: string | null;
  pullRequest: string;
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
}

export interface SonarIssue {
  rule?: unknown;
  type?: unknown;
  impacts?: unknown;
  tags?: unknown;
  status?: unknown;
  resolution?: unknown;
}

export interface SonarHotspot {
  ruleKey?: unknown;
  vulnerabilityProbability?: unknown;
  status?: unknown;
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** Hosts that are SonarQube Cloud, where `organization` is required. */
export function isSonarCloud(hostUrl: string): boolean {
  try {
    const host = new URL(hostUrl).hostname.toLowerCase();
    return (
      host === 'sonarcloud.io' ||
      host.endsWith('.sonarcloud.io') ||
      host === 'sonarqube.us' ||
      host.endsWith('.sonarqube.us')
    );
  } catch {
    return false;
  }
}

/** `http(s)://host[/context]` without a trailing slash, or null. */
export function normalizeHostUrl(raw: string): string | null {
  try {
    const url = new URL(raw.trim());
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (url.username || url.password || url.search || url.hash) return null;
    return url.toString().replace(/\/+$/, '');
  } catch {
    return null;
  }
}

/** `ceTaskId` from the scanner's `report-task.txt` (Java properties format). */
export function parseReportTask(text: string): string | null {
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*ceTaskId\s*[=:]\s*(\S+)\s*$/.exec(line);
    if (m && /^[A-Za-z0-9_-]{1,64}$/.test(m[1])) return m[1];
  }
  return null;
}

async function get(cfg: SonarConfig, path: string, params: Record<string, string>): Promise<Json> {
  const url = new URL(`${cfg.hostUrl}/${path}`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  if (cfg.organization) url.searchParams.set('organization', cfg.organization);
  const doFetch = cfg.fetchImpl ?? fetch;
  let res: Response;
  try {
    res = await doFetch(url, {
      headers: {
        // Public SonarQube Cloud projects can be read anonymously, so an empty token sends no credential.
        ...(cfg.token ? { Authorization: `Bearer ${cfg.token}` } : {}),
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      redirect: 'error',
    });
  } catch (error) {
    throw new SonarError('http', `${path} request failed (${error instanceof Error ? error.name : 'error'})`);
  }
  if (res.status === 401 || res.status === 403)
    throw new SonarError('auth', `${path} returned HTTP ${res.status}`, res.status);
  if (!res.ok) throw new SonarError('http', `${path} returned HTTP ${res.status}`, res.status);
  try {
    const body: unknown = await res.json();
    if (!isObject(body)) throw new Error('not an object');
    return body;
  } catch {
    throw new SonarError('http', `${path} returned a body that is not JSON`);
  }
}

/**
 * Polls `api/ce/task` until the scanner's background task finishes, and checks it analysed this pull request.
 * Sonar's own quality gate action does the same.
 */
export async function waitForAnalysis(cfg: SonarConfig, taskId: string, timeoutSec: number): Promise<void> {
  const sleep = cfg.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const deadline = Date.now() + timeoutSec * 1000;
  for (;;) {
    const body = await get(cfg, 'api/ce/task', { id: taskId });
    const task = isObject(body.task) ? body.task : {};
    const status = String(task.status ?? '');
    if (status === 'SUCCESS') {
      if (task.pullRequest === undefined || task.pullRequest === null) {
        throw new SonarError('no-pr', 'the analysis is a branch analysis, not a pull request analysis');
      }
      if (String(task.pullRequest) !== cfg.pullRequest) {
        throw new SonarError('mismatch', 'the analysis belongs to a different pull request');
      }
      return;
    }
    if (status === 'FAILED' || status === 'CANCELED')
      throw new SonarError('failed', `the analysis task ended as ${status}`);
    if (Date.now() + POLL_INTERVAL_MS > deadline)
      throw new SonarError('timeout', 'the analysis did not finish in time');
    await sleep(POLL_INTERVAL_MS);
  }
}

/**
 * `new_vulnerabilities` on the pull request. A 404 means Sonar has no analysis for this pull request,
 * which is what a Community Build (no pull request analysis) or a missing scan looks like.
 */
export async function fetchNewVulnerabilityCount(cfg: SonarConfig): Promise<number | null> {
  let body: Json;
  try {
    body = await get(cfg, 'api/measures/component', {
      component: cfg.projectKey,
      pullRequest: cfg.pullRequest,
      metricKeys: 'new_vulnerabilities',
    });
  } catch (error) {
    if (error instanceof SonarError && (error.status === 404 || error.status === 400)) {
      throw new SonarError('no-pr', 'Sonar has no analysis for this pull request', error.status);
    }
    throw error;
  }
  const component = isObject(body.component) ? body.component : {};
  for (const m of asArray(component.measures)) {
    if (!isObject(m) || m.metric !== 'new_vulnerabilities') continue;
    // Pull request measures sit in `periods[0]` on Cloud and `period` on Server, sometimes `value`.
    const period = isObject(m.period)
      ? m.period
      : isObject(asArray(m.periods)[0])
        ? (asArray(m.periods)[0] as Json)
        : m;
    const n = Number(period.value ?? m.value);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

async function pageAll(
  cfg: SonarConfig,
  path: string,
  params: Record<string, string>,
  listKey: string,
): Promise<unknown[]> {
  const out: unknown[] = [];
  for (let p = 1; out.length < SONAR_MAX_ISSUES; p++) {
    const body = await get(cfg, path, {
      ...params,
      p: String(p),
      ps: String(SONAR_PAGE_SIZE),
    });
    const items = asArray(body[listKey]);
    out.push(...items);
    const paging = isObject(body.paging) ? body.paging : {};
    const total = Number(paging.total ?? body.total);
    if (items.length < SONAR_PAGE_SIZE || (Number.isFinite(total) && p * SONAR_PAGE_SIZE >= total)) break;
  }
  return out.slice(0, SONAR_MAX_ISSUES);
}

/**
 * Open vulnerabilities on the pull request. `api/issues/search` first: it is the only one on SonarQube Cloud.
 * `api/issues/list` (some Server versions) when search rejects `pullRequest`, or returns nothing while
 * the pull request's measures say there are new vulnerabilities.
 */
export async function fetchPrIssues(cfg: SonarConfig, expectedNew: number | null): Promise<SonarIssue[]> {
  let issues: unknown[] | null = null;
  try {
    issues = await pageAll(
      cfg,
      'api/issues/search',
      {
        componentKeys: cfg.projectKey,
        pullRequest: cfg.pullRequest,
        types: 'VULNERABILITY',
        resolved: 'false',
      },
      'issues',
    );
  } catch (error) {
    if (!(error instanceof SonarError) || (error.status !== 400 && error.status !== 404)) throw error;
  }
  if (issues === null || (issues.length === 0 && (expectedNew ?? 0) > 0)) {
    try {
      issues = await pageAll(
        cfg,
        'api/issues/list',
        {
          project: cfg.projectKey,
          pullRequest: cfg.pullRequest,
          types: 'VULNERABILITY',
        },
        'issues',
      );
    } catch (error) {
      if (!(error instanceof SonarError) || (error.status !== 400 && error.status !== 404)) throw error;
      issues = issues ?? [];
    }
  }
  if (issues.length === 0 && (expectedNew ?? 0) > 0) {
    // The pull request has new vulnerabilities the token cannot see.
    throw new SonarError('auth', 'no issues visible to the token');
  }
  return issues.filter(isObject).filter((i) => i.resolution === undefined || i.resolution === null);
}

/** Hotspots still to review on the pull request. */
export async function fetchHotspots(cfg: SonarConfig): Promise<SonarHotspot[]> {
  const hotspots = await pageAll(
    cfg,
    'api/hotspots/search',
    {
      projectKey: cfg.projectKey,
      pullRequest: cfg.pullRequest,
      status: 'TO_REVIEW',
    },
    'hotspots',
  );
  return hotspots.filter(isObject);
}

/**
 * `securityStandards` (e.g. `cwe:89`, `owaspTop10-2021:a3`) per rule, one `api/rules/show` per distinct rule.
 * A rule that fails to load is left out, and its findings fall back to issue tags.
 */
export async function fetchRuleStandards(cfg: SonarConfig, ruleKeys: string[]): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  for (const key of [...new Set(ruleKeys)]) {
    try {
      const body = await get(cfg, 'api/rules/show', { key });
      const rule = isObject(body.rule) ? body.rule : {};
      out.set(
        key,
        asArray(rule.securityStandards).filter((s): s is string => typeof s === 'string'),
      );
    } catch (error) {
      if (error instanceof SonarError && error.kind === 'auth') throw error;
    }
  }
  return out;
}

/** Head commit of the latest analysis of this pull request, or null when Sonar has none yet. */
export async function fetchPullRequestCommit(cfg: SonarConfig): Promise<string | null> {
  const body = await get(cfg, 'api/project_pull_requests/list', { project: cfg.projectKey });
  for (const pr of asArray(body.pullRequests)) {
    if (!isObject(pr) || String(pr.key) !== cfg.pullRequest) continue;
    const sha = isObject(pr.commit) ? pr.commit.sha : undefined;
    return typeof sha === 'string' ? sha : null;
  }
  return null;
}

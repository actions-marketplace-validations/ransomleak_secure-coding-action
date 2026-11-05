import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import type { SonarConfig } from './sonar-client.ts';
import {
  fetchPrIssues,
  isSonarCloud,
  normalizeHostUrl,
  parseReportTask,
  SONAR_MAX_ISSUES,
  SONAR_PAGE_SIZE,
} from './sonar-client.ts';
import { readSonarFindings, SONAR_CLOUD_NO_PR_MESSAGE, SONAR_NO_PR_MESSAGE, SONAR_TOKEN_MESSAGE } from './sonar-source.ts';

const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`../fixtures/sonar/${name}.json`, import.meta.url), 'utf8'));

type Route = (url: URL) => { status: number; body: unknown } | undefined;

function mockFetch(route: Route, seen: URL[] = [], headers: Headers[] = []): typeof fetch {
  return (async (input: URL, init?: RequestInit) => {
    const url = new URL(String(input));
    seen.push(url);
    headers.push(new Headers(init?.headers));
    const hit = route(url) ?? {
      status: 404,
      body: { errors: [{ msg: `Unknown url : ${url.pathname}` }] },
    };
    return new Response(JSON.stringify(hit.body), { status: hit.status });
  }) as typeof fetch;
}

const cfg = (fetchImpl: typeof fetch, extra: Partial<SonarConfig> = {}): SonarConfig => ({
  hostUrl: 'https://sonarcloud.io',
  token: 'secret-token',
  projectKey: 'cozyGarage_BookiE',
  organization: 'cozygarage',
  pullRequest: '2484',
  fetchImpl,
  sleep: async () => {},
  ...extra,
});

/** Recorded SonarQube Cloud responses for the public project cozyGarage_BookiE, pull request 2484. */
const cloudRoute: Route = (url) => {
  const key = url.searchParams.get('key');
  switch (url.pathname) {
    case '/api/measures/component':
      return { status: 200, body: fixture('cloud-measures-pr') };
    case '/api/issues/search':
      return { status: 200, body: fixture('cloud-issues-search') };
    case '/api/issues/list':
      return { status: 404, body: fixture('cloud-issues-list-404') };
    case '/api/hotspots/search':
      return { status: 200, body: fixture('cloud-hotspots-search') };
    case '/api/rules/show':
      if (key === 'jssecurity:S8705') return { status: 200, body: fixture('cloud-rule-jssecurity-S8705') };
      if (key === 'javascript:S4036') return { status: 200, body: fixture('cloud-rule-javascript-S4036') };
      return { status: 404, body: {} };
    case '/api/ce/task':
      return {
        status: 200,
        body: { task: { id: 'T1', status: 'SUCCESS', pullRequest: '2484' } },
      };
  }
  return undefined;
};

const opts = {
  includeHotspots: false,
  waitTimeoutSec: 300,
  reportTask: null,
  log: () => {},
};

test('host helpers', () => {
  assert.equal(normalizeHostUrl('https://sonar.example.com/sonarqube/'), 'https://sonar.example.com/sonarqube');
  assert.equal(normalizeHostUrl('ftp://x'), null);
  assert.equal(normalizeHostUrl('https://u:p@x'), null);
  assert.equal(isSonarCloud('https://sonarcloud.io'), true);
  assert.equal(isSonarCloud('https://sonar.example.com'), false);
  assert.equal(
    parseReportTask('projectKey=a\nceTaskId=AaGr-PdcbqwN_iczoDVb4f\nceTaskUrl=https://x'),
    'AaGr-PdcbqwN_iczoDVb4f',
  );
  assert.equal(parseReportTask('ceTaskUrl=https://x'), null);
});

test('cloud end to end: Bearer token, organization param, CWE findings, hotspots off by default', async () => {
  const seen: URL[] = [];
  const headers: Headers[] = [];
  const result = await readSonarFindings(cfg(mockFetch(cloudRoute, seen, headers)), opts);
  assert.deepEqual(result, {
    findings: [
      { toolName: 'SonarQube', cwe: ['CWE-426', 'CWE-427'], cveOrGhsa: false, owaspTop10: ['A8:2021'] },
      { toolName: 'SonarQube', cwe: ['CWE-20', 'CWE-88'], cveOrGhsa: false },
    ],
  });
  assert.ok(seen.every((u) => u.origin === 'https://sonarcloud.io'));
  assert.ok(seen.every((u) => u.searchParams.get('organization') === 'cozygarage'));
  assert.ok(headers.every((h) => h.get('authorization') === 'Bearer secret-token'));
  assert.ok(!seen.some((u) => u.pathname === '/api/hotspots/search'));
  assert.ok(!seen.some((u) => u.pathname === '/api/issues/list'), 'search worked, no fallback');
  const search = seen.find((u) => u.pathname === '/api/issues/search');
  assert.equal(search?.searchParams.get('pullRequest'), '2484');
  assert.equal(search?.searchParams.get('types'), 'VULNERABILITY');
  assert.equal(search?.searchParams.get('resolved'), 'false');
});

test('waits on the report task and checks the pull request key', async () => {
  let polls = 0;
  const route: Route = (url) => {
    if (url.pathname === '/api/ce/task') {
      polls++;
      return {
        status: 200,
        body: {
          task: {
            status: polls < 3 ? 'IN_PROGRESS' : 'SUCCESS',
            pullRequest: '2484',
          },
        },
      };
    }
    return cloudRoute(url);
  };
  const r = await readSonarFindings(cfg(mockFetch(route)), {
    ...opts,
    reportTask: 'ceTaskId=T1\n',
  });
  assert.ok('findings' in r);
  assert.equal(polls, 3);

  const other: Route = (url) =>
    url.pathname === '/api/ce/task'
      ? { status: 200, body: { task: { status: 'SUCCESS', pullRequest: '7' } } }
      : cloudRoute(url);
  const mismatch = await readSonarFindings(cfg(mockFetch(other)), {
    ...opts,
    reportTask: 'ceTaskId=T1',
  });
  assert.match('skip' in mismatch ? mismatch.skip : '', /different pull request/);

  const branch: Route = (url) =>
    url.pathname === '/api/ce/task'
      ? { status: 200, body: { task: { status: 'SUCCESS', branch: 'main' } } }
      : cloudRoute(url);
  assert.deepEqual(
    await readSonarFindings(cfg(mockFetch(branch)), {
      ...opts,
      reportTask: 'ceTaskId=T1',
    }),
    {
      skip: SONAR_CLOUD_NO_PR_MESSAGE,
    },
  );
});

test('timeout skips with a log line', async () => {
  const route: Route = (url) =>
    url.pathname === '/api/ce/task' ? { status: 200, body: { task: { status: 'PENDING' } } } : cloudRoute(url);
  const r = await readSonarFindings(cfg(mockFetch(route)), {
    ...opts,
    waitTimeoutSec: 0,
    reportTask: 'ceTaskId=T1',
  });
  assert.match('skip' in r ? r.skip : '', /did not finish within 0 seconds/);
});

test('an empty token reads anonymously: no Authorization header', async () => {
  const headers: Headers[] = [];
  const r = await readSonarFindings(cfg(mockFetch(cloudRoute, [], headers), { token: '' }), opts);
  assert.ok('findings' in r);
  assert.ok(headers.length > 0 && headers.every((h) => h.get('authorization') === null));
});

test('401 and 403 give the token message', async () => {
  for (const status of [401, 403]) {
    const r = await readSonarFindings(cfg(mockFetch(() => ({ status, body: {} }))), opts);
    assert.deepEqual(r, { skip: SONAR_TOKEN_MESSAGE });
  }
});

test('empty issues while the pull request has new vulnerabilities is a token problem', async () => {
  const route: Route = (url) =>
    url.pathname === '/api/issues/search'
      ? { status: 200, body: { paging: { total: 0 }, issues: [] } }
      : cloudRoute(url);
  assert.deepEqual(await readSonarFindings(cfg(mockFetch(route)), opts), {
    skip: SONAR_TOKEN_MESSAGE,
  });
});

test('no pull request analysis (Community Build or no scan) points to SARIF', async () => {
  const route: Route = (url) =>
    url.pathname === '/api/measures/component'
      ? {
          status: 404,
          body: {
            errors: [{ msg: "Component 'k' of pull request '2484' not found" }],
          },
        }
      : cloudRoute(url);
  assert.deepEqual(await readSonarFindings(cfg(mockFetch(route)), { ...opts, waitTimeoutSec: 0 }), {
    skip: SONAR_CLOUD_NO_PR_MESSAGE,
  });
});

test('falls back to issues/list when search rejects pullRequest', async () => {
  const seen: URL[] = [];
  const route: Route = (url) => {
    if (url.pathname === '/api/issues/search') return { status: 400, body: { errors: [{ msg: 'unknown parameter' }] } };
    if (url.pathname === '/api/issues/list') return { status: 200, body: fixture('cloud-issues-search') };
    return cloudRoute(url);
  };
  const issues = await fetchPrIssues(
    cfg(mockFetch(route, seen), {
      organization: null,
      hostUrl: 'https://sonar.example.com',
    }),
    2,
  );
  assert.equal(issues.length, 2);
  const list = seen.find((u) => u.pathname === '/api/issues/list');
  assert.equal(list?.searchParams.get('project'), 'cozyGarage_BookiE');
  assert.equal(list?.searchParams.get('organization'), null, 'no organization on Server');
});

test('pages with ps=500 and caps at 2,000 issues', async () => {
  let pages = 0;
  const route: Route = (url) => {
    if (url.pathname !== '/api/issues/search') return cloudRoute(url);
    pages++;
    assert.equal(url.searchParams.get('ps'), String(SONAR_PAGE_SIZE));
    const issues = Array.from({ length: SONAR_PAGE_SIZE }, () => ({
      rule: 'r',
      type: 'VULNERABILITY',
    }));
    return { status: 200, body: { paging: { total: 10_000 }, issues } };
  };
  const issues = await fetchPrIssues(cfg(mockFetch(route)), 0);
  assert.equal(issues.length, SONAR_MAX_ISSUES);
  assert.equal(pages, SONAR_MAX_ISSUES / SONAR_PAGE_SIZE);
});

test('hotspots only when opted in', async () => {
  const seen: URL[] = [];
  await readSonarFindings(cfg(mockFetch(cloudRoute, seen)), {
    ...opts,
    includeHotspots: true,
  });
  const h = seen.find((u) => u.pathname === '/api/hotspots/search');
  assert.equal(h?.searchParams.get('status'), 'TO_REVIEW');
  assert.equal(h?.searchParams.get('projectKey'), 'cozyGarage_BookiE');
});

test('a network failure skips without leaking the token', async () => {
  const failing = (async () => {
    throw new TypeError('fetch failed');
  }) as unknown as typeof fetch;
  const r = await readSonarFindings(cfg(failing), opts);
  assert.ok('skip' in r && !r.skip.includes('secret-token'));
});

test('without report-task.txt on Cloud, waits until the pull request analysis appears', async () => {
  let calls = 0;
  const route: Route = (url) => {
    if (url.pathname === '/api/measures/component' && ++calls < 3) return { status: 404, body: {} };
    return cloudRoute(url);
  };
  const r = await readSonarFindings(cfg(mockFetch(route)), { ...opts, waitTimeoutSec: 600 });
  assert.ok('findings' in r);
  assert.equal(calls >= 3, true);
});

test('without report-task.txt on Cloud, a never-appearing pull request ends as no-PR', async () => {
  const route: Route = () => ({ status: 404, body: {} });
  const r = await readSonarFindings(cfg(mockFetch(route)), { ...opts, waitTimeoutSec: 0 });
  assert.deepEqual(r, { skip: SONAR_CLOUD_NO_PR_MESSAGE });
});

test('on a Server host the no-PR message mentions Community Build', async () => {
  const route: Route = () => ({ status: 404, body: {} });
  const r = await readSonarFindings(cfg(mockFetch(route), { hostUrl: 'https://sonar.example.com', organization: null }), opts);
  assert.deepEqual(r, { skip: SONAR_NO_PR_MESSAGE });
});

test('without report-task.txt on Cloud, waits until the analysis is for the head commit', async () => {
  let calls = 0;
  const route: Route = (url) => {
    if (url.pathname === '/api/project_pull_requests/list') {
      const sha = ++calls < 3 ? 'oldsha' : 'headsha';
      return { status: 200, body: { pullRequests: [{ key: '2484', commit: { sha } }] } };
    }
    return cloudRoute(url);
  };
  const r = await readSonarFindings(cfg(mockFetch(route)), { ...opts, waitTimeoutSec: 600, headSha: 'headsha' });
  assert.ok('findings' in r);
  assert.equal(calls, 3);
});

test('a stale analysis at the timeout posts nothing and says why', async () => {
  const route: Route = (url) =>
    url.pathname === '/api/project_pull_requests/list'
      ? { status: 200, body: { pullRequests: [{ key: '2484', commit: { sha: 'oldsha' } }] } }
      : cloudRoute(url);
  const r = await readSonarFindings(cfg(mockFetch(route)), { ...opts, waitTimeoutSec: 0, headSha: 'headsha' });
  assert.match('skip' in r ? r.skip : '', /had not analysed the latest commit/);
});

test('with a head commit and no PR listed at the timeout, the no-PR message is used', async () => {
  const route: Route = (url) =>
    url.pathname === '/api/project_pull_requests/list' ? { status: 200, body: { pullRequests: [] } } : cloudRoute(url);
  const r = await readSonarFindings(cfg(mockFetch(route)), { ...opts, waitTimeoutSec: 0, headSha: 'headsha' });
  assert.deepEqual(r, { skip: SONAR_CLOUD_NO_PR_MESSAGE });
});

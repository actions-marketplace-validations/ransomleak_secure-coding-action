import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { hotspotToFinding, issueToFinding, ruleKeysOf, sonarFindings } from './sonar-findings.ts';

const fixture = (name: string): Record<string, any> =>
  JSON.parse(readFileSync(new URL(`../fixtures/sonar/${name}.json`, import.meta.url), 'utf8'));

const standardsFromFixtures = (): Map<string, string[]> => {
  const out = new Map<string, string[]>();
  for (const name of ['cloud-rule-jssecurity-S8705', 'cloud-rule-javascript-S4036']) {
    const { rule } = fixture(name);
    out.set(rule.key, rule.securityStandards);
  }
  return out;
};

test('cloud issues/search with rules/show standards', () => {
  const { issues } = fixture('cloud-issues-search');
  const standards = standardsFromFixtures();
  assert.deepEqual(ruleKeysOf(issues, []), ['javascript:S4036', 'jssecurity:S8705']);
  assert.deepEqual(sonarFindings(issues, [], standards), [
    { toolName: 'SonarQube', cwe: ['CWE-426', 'CWE-427'], cveOrGhsa: false, owaspTop10: ['A8:2021'] },
    { toolName: 'SonarQube', cwe: ['CWE-20', 'CWE-88'], cveOrGhsa: false },
  ]);
});

test('output holds no paths, messages or rule keys', () => {
  const text = JSON.stringify(sonarFindings(fixture('cloud-issues-search').issues, [], standardsFromFixtures()));
  for (const leak of ['selftest', 'cozyGarage', 'PATH', 'S4036', 'owaspTop10-2021:', 'owaspTop10:a1'])
    assert.ok(!text.includes(leak), leak);
});

test('impacts-only issue counts, a non-security type does not', () => {
  const standards = new Map([['r', ['cwe:89']]]);
  assert.deepEqual(issueToFinding({ rule: 'r', impacts: [{ softwareQuality: 'SECURITY' }] }, standards)?.cwe, [
    'CWE-89',
  ]);
  assert.equal(issueToFinding({ rule: 'r', impacts: [{ softwareQuality: 'MAINTAINABILITY' }] }, standards), null);
  assert.equal(
    issueToFinding(
      {
        rule: 'r',
        type: 'CODE_SMELL',
        impacts: [{ softwareQuality: 'SECURITY' }],
      },
      standards,
    ),
    null,
  );
});

test('missing rule metadata falls back to issue tags; a bare cwe tag names nothing', () => {
  assert.deepEqual(issueToFinding({ rule: 'x', type: 'VULNERABILITY', tags: ['cwe-79', 'owasp-a3'] }, new Map())?.cwe, [
    'CWE-79',
  ]);
  assert.equal(issueToFinding({ rule: 'x', type: 'VULNERABILITY', tags: ['cwe', 'former-hotspot'] }, new Map()), null);
});

test('OWASP 2021 standards are sent as A{n}:2021; 2017 and other standards are not', () => {
  const standards = new Map([
    ['r', ['owaspTop10-2021:a10', 'owaspTop10:a1', 'owaspTop10-2021:A03', 'owaspAsvs-4.0:5.2.6']],
  ]);
  assert.deepEqual(issueToFinding({ rule: 'r', type: 'VULNERABILITY' }, standards), {
    toolName: 'SonarQube',
    cwe: [],
    cveOrGhsa: false,
    owaspTop10: ['A10:2021', 'A3:2021'],
  });
  assert.equal(issueToFinding({ rule: 'r', type: 'VULNERABILITY' }, new Map([['r', ['owaspTop10:a1']]])), null);
});

test('CWE-only findings keep the original payload shape (no owaspTop10 key)', () => {
  const f = issueToFinding({ rule: 'r', type: 'VULNERABILITY' }, new Map([['r', ['cwe:89']]]));
  assert.ok(f && !('owaspTop10' in f));
});

test('the fixture rule S4036 carries its OWASP 2021 category', () => {
  const { rule } = fixture('cloud-rule-javascript-S4036');
  const f = issueToFinding({ rule: rule.key, type: 'VULNERABILITY' }, standardsFromFixtures());
  assert.deepEqual(f?.owaspTop10, ['A8:2021']);
});

test('hotspots: only HIGH or MEDIUM probability', () => {
  const { hotspots } = fixture('cloud-hotspots-search');
  const standards = new Map([['githubactions:S7637', ['cwe:494', 'cwe:829', 'owaspTop10-2021:a8']]]);
  assert.equal(hotspotToFinding(hotspots[0], standards), null, 'fixture is LOW');
  assert.deepEqual(hotspotToFinding({ ...hotspots[0], vulnerabilityProbability: 'HIGH' }, standards), {
    toolName: 'SonarQube',
    cwe: ['CWE-494', 'CWE-829'],
    cveOrGhsa: false,
    owaspTop10: ['A8:2021'],
  });
  assert.equal(
    hotspotToFinding(
      {
        ...hotspots[0],
        vulnerabilityProbability: 'MEDIUM',
        status: 'REVIEWED',
      },
      standards,
    ),
    null,
  );
});

test('dedupes issues and hotspots with the same CWE set', () => {
  const standards = new Map([
    ['a', ['cwe:89']],
    ['b', ['cwe:89']],
  ]);
  const out = sonarFindings(
    [
      { rule: 'a', type: 'VULNERABILITY' },
      { rule: 'b', type: 'VULNERABILITY' },
    ],
    [{ ruleKey: 'a', vulnerabilityProbability: 'HIGH', status: 'TO_REVIEW' }],
    standards,
  );
  assert.equal(out.length, 1);
});

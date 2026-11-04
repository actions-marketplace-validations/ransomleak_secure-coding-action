import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { extractFindings, MAX_FINDINGS, MAX_IDENTIFIER_LENGTH, SarifError } from './sarif.ts';

const fixture = (name: string): string =>
  readFileSync(new URL(`../fixtures/${name}.sarif`, import.meta.url), 'utf8');

test('semgrep: leading CWE only, titles cut', () => {
  const out = extractFindings(fixture('semgrep'));
  assert.deepEqual(out, [
    {
      toolName: 'Semgrep OSS',
      cwe: ['CWE-704'],
      cveOrGhsa: false,
    },
  ]);
});

test('trivy: CVE from rule id, only fired rules, deduped by identifier set', () => {
  const out = extractFindings(fixture('trivy'));
  assert.deepEqual(out, [{ toolName: 'Trivy', cwe: [], cveOrGhsa: true }]);
});

test('gitleaks: secrets tool kept with no identifiers', () => {
  assert.deepEqual(extractFindings(fixture('gitleaks')), [
    { toolName: 'gitleaks', cwe: [], cveOrGhsa: false },
  ]);
});

test('codeql: extension rules and rule.id, unfired rules ignored', () => {
  const out = extractFindings(fixture('codeql'));
  assert.deepEqual(out, [
    { toolName: 'CodeQL', cwe: ['external/cwe/cwe-089', 'external/cwe/cwe-090'], cveOrGhsa: false },
    { toolName: 'CodeQL', cwe: ['external/cwe/cwe-079'], cveOrGhsa: false },
  ]);
  assert.ok(!JSON.stringify(out).includes('999'));
});

test('output holds no paths, messages or snippets', () => {
  for (const name of ['semgrep', 'trivy', 'gitleaks', 'codeql']) {
    const text = JSON.stringify(extractFindings(fixture(name)));
    assert.ok(!text.includes('sample.'), name);
    assert.ok(!text.includes('redacted'), name);
    assert.ok(!text.includes('uri'), name);
    assert.deepEqual(
      Object.keys(JSON.parse(text)[0]).sort(),
      ['cveOrGhsa', 'cwe', 'toolName'],
    );
  }
});

test('GHSA tag marks cveOrGhsa', () => {
  const sarif = {
    runs: [
      {
        tool: { driver: { name: 'X', rules: [{ id: 'r1', properties: { tags: ['GHSA-abcd-1234-wxyz'] } }] } },
        results: [{ ruleId: 'r1' }],
      },
    ],
  };
  assert.equal(extractFindings(sarif)[0].cveOrGhsa, true);
});

test('limits: identifiers per list, length, finding count', () => {
  const tags = Array.from({ length: 15 }, (_, i) => `CWE-${i + 1}`);
  const many = {
    runs: [
      {
        tool: { driver: { name: 'T', rules: [{ id: 'a', properties: { tags } }] } },
        results: [{ ruleId: 'a' }],
      },
    ],
  };
  assert.equal(extractFindings(many)[0].cwe.length, 10);

  const longId = { runs: [{ tool: { driver: { name: 'T', rules: [{ id: 'a', properties: { tags: [`CWE-${'1'.repeat(200)}`] } }] } }, results: [{ ruleId: 'a' }] }] };
  assert.deepEqual(extractFindings(longId), []);

  const rules = Array.from({ length: 300 }, (_, i) => ({ id: `r${i}`, properties: { tags: [`CWE-${i + 1}`] } }));
  const wide = {
    runs: [{ tool: { driver: { name: 'T', rules } }, results: rules.map((r) => ({ ruleId: r.id })) }],
  };
  const out = extractFindings(wide);
  assert.equal(out.length, MAX_FINDINGS);
  assert.ok(out.every((f) => f.cwe.every((c) => c.length <= MAX_IDENTIFIER_LENGTH)));
});

test('baselineState: only new and updated count, absent field counts', () => {
  const run = (results: unknown[]) => ({
    runs: [{ tool: { driver: { name: 'T', rules: [{ id: 'a', properties: { tags: ['CWE-89'] } }] } }, results }],
  });
  for (const state of ['new', 'updated']) {
    assert.equal(extractFindings(run([{ ruleId: 'a', baselineState: state }])).length, 1, state);
  }
  for (const state of ['unchanged', 'absent']) {
    assert.deepEqual(extractFindings(run([{ ruleId: 'a', baselineState: state }])), [], state);
  }
  assert.equal(extractFindings(run([{ ruleId: 'a' }])).length, 1);
});

test('invalid JSON and wrong shape throw SarifError', () => {
  assert.throws(() => extractFindings('{nope'), SarifError);
  assert.throws(() => extractFindings({}), SarifError);
  assert.throws(() => extractFindings(null), SarifError);
});

test('only failing, unsuppressed results count', () => {
  const sarif = (result: object) =>
    extractFindings(
      JSON.stringify({
        runs: [
          {
            tool: { driver: { name: 'Semgrep OSS', rules: [{ id: 'r', properties: { tags: ['CWE-89'] } }] } },
            results: [{ ruleId: 'r', ...result }],
          },
        ],
      }),
    );
  assert.equal(sarif({}).length, 1);
  assert.equal(sarif({ kind: 'fail' }).length, 1);
  assert.equal(sarif({ suppressions: [] }).length, 1);
  for (const kind of ['pass', 'open', 'review', 'notApplicable', 'informational']) {
    assert.equal(sarif({ kind }).length, 0, kind);
  }
  assert.equal(sarif({ suppressions: [{ kind: 'inSource' }] }).length, 0);
});

test('rule ids ending in an advisory id (Azure DevOps dependency scanning) mark cveOrGhsa', () => {
  const sarif = (ruleId: string) => ({
    runs: [{ tool: { driver: { name: 'AdvancedSecurity' } }, results: [{ ruleId }] }],
  });
  for (const id of ['DEP1001_GHSA-68w8-qjq3-2gfm', 'DEP1001_CVE-2021-44228', 'CVE-2021-44228']) {
    assert.deepEqual(extractFindings(sarif(id)), [{ toolName: 'AdvancedSecurity', cwe: [], cveOrGhsa: true }], id);
  }
  for (const id of ['DEP1001GHSA-68w8-qjq3-2gfm', 'GHSA-68w8-qjq3-2gfm_extra', 'XCVE-2021-44228']) {
    assert.deepEqual(extractFindings(sarif(id)), [], id);
  }
});

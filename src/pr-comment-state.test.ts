import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

import { GITHUB_COMMENT_MARKER, mergeLesson, parseCommentState, renderComment } from './pr-comment-state.ts';

const ORIGIN = 'https://app.ransomleak.com';

test('render then parse round-trips and honors allowedOrigin', () => {
  const lessons = [
    { moduleKey: 'sql-injection', title: 'SQL injection', launchUrl: `${ORIGIN}/l/abc`, done: false },
  ];
  const body = renderComment(lessons);
  assert.ok(body.includes(GITHUB_COMMENT_MARKER));
  assert.deepEqual(parseCommentState(body, ORIGIN), lessons);
  assert.deepEqual(parseCommentState(body, 'https://evil.example'), []);
});

test('mergeLesson keeps done sticky', () => {
  const done = { moduleKey: 'a', title: 'A', launchUrl: `${ORIGIN}/x`, done: true };
  assert.equal(mergeLesson([done], { ...done, done: false })[0].done, true);
});

const STAMP = '2026-11-03T20:22:48.482Z';
const doneLesson = { moduleKey: 'k', title: 'T', launchUrl: `${ORIGIN}/l/k`, done: true, completedAt: STAMP };

test('done line shows a readable UTC date and keeps the ISO stamp in the marker', () => {
  const body = renderComment([doneLesson]);
  assert.ok(body.includes('· completed via this link on 3 Nov 2026 <!-- ransomleak:github:lesson:k:done:' + STAMP + ' -->'));
  assert.ok(!body.includes(' ' + STAMP + ' '));
  assert.deepEqual(parseCommentState(body, ORIGIN), [doneLesson]);
});

test('old visible-stamp form still parses', () => {
  const old = `- ✅ [T](${ORIGIN}/l/k) · completed via this link ${STAMP} <!-- ransomleak:github:lesson:k:done -->`;
  assert.deepEqual(parseCommentState(old, ORIGIN), [doneLesson]);
});

test('hostile marker value is dropped, lesson kept', () => {
  const bad = `- ✅ [T](${ORIGIN}/l/k) · completed via this link on 3 Nov 2026 <!-- ransomleak:github:lesson:k:done:<script>x -->`;
  assert.deepEqual(parseCommentState(bad, ORIGIN), [{ ...doneLesson, completedAt: undefined }].map(({ completedAt, ...l }) => l));
});

test('intro wording is singular for one lesson and plural for several', () => {
  const one = renderComment([doneLesson]);
  assert.ok(one.includes('reported this type of issue on'));
  const two = renderComment([doneLesson, { ...doneLesson, moduleKey: 'j' }]);
  assert.ok(two.includes('reported these types of issues on'));
});

test('azure flavour renders the same text with its own markers', () => {
  const lessons = [
    { moduleKey: 'sql-injection', title: 'SQL injection', launchUrl: `${ORIGIN}/l/abc`, done: false },
    { moduleKey: 'xss', title: 'XSS', launchUrl: `${ORIGIN}/l/def`, done: true, completedAt: '2026-11-03T10:00:00.000Z' },
  ];
  const github = renderComment(lessons);
  const azure = renderComment(lessons, { markdownFlavor: 'azure' });
  assert.equal(
    azure,
    github
      .replaceAll('ransomleak:github:', 'ransomleak:azure:')
      .replace('/integrations/github/', '/integrations/azure-devops/'),
  );
  assert.ok(azure.endsWith('<!-- ransomleak:azure:comment -->\n'));
  assert.deepEqual(parseCommentState(azure, ORIGIN, { markdownFlavor: 'azure' }), lessons);
  assert.deepEqual(parseCommentState(azure, ORIGIN), []);
  assert.deepEqual(parseCommentState(github, ORIGIN, { markdownFlavor: 'azure' }), []);
});

test('copy matches the backend file when it is present', (t) => {
  const backend = new URL('../../../backend/src/secure-coding-jit/utils/pr-comment-state.util.ts', import.meta.url);
  if (!existsSync(backend)) return t.skip('backend file not present (standalone checkout)');
  const copy = readFileSync(new URL('./pr-comment-state.ts', import.meta.url), 'utf8');
  const verbatim = copy.slice(copy.indexOf('// --- verbatim copy ---\n') + '// --- verbatim copy ---\n'.length);
  const original = readFileSync(backend, 'utf8').split('\n').slice(1).join('\n');
  assert.equal(verbatim, original);
});

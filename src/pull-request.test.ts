import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parseCommentState, renderComment } from './pr-comment-state.ts';
import { isFromFork, planCommentCleanup } from './pull-request.ts';

const ORIGIN = 'https://app.ransomleak.com';
const repo = (full_name: string, fork = false) => ({ repo: { full_name, fork } });
const lesson = (moduleKey: string, done = false) => ({
  moduleKey,
  title: moduleKey,
  launchUrl: `${ORIGIN}/l/${moduleKey}`,
  done,
});

test('fork check compares names only', () => {
  assert.equal(isFromFork({ head: repo('a/b'), base: repo('a/b') }), false);
  assert.equal(isFromFork({ head: repo('a/b', true), base: repo('a/b', true) }), false, 'same-repo PR in a fork');
  assert.equal(isFromFork({ head: repo('x/b', true), base: repo('a/b') }), true);
  assert.equal(isFromFork({ head: { repo: null }, base: repo('a/b') }), true, 'deleted head');
});

test('one comment needs no cleanup', () => {
  assert.equal(planCommentCleanup([{ id: 1, body: renderComment([lesson('a')]) }], ORIGIN), null);
});

test('keeps the lowest id, merges lessons, done is sticky', () => {
  const plan = planCommentCleanup(
    [
      { id: 9, body: renderComment([lesson('a', true), lesson('b')]) },
      { id: 3, body: renderComment([lesson('a')]) },
    ],
    ORIGIN,
  );
  assert.equal(plan?.keepId, 3);
  assert.deepEqual(plan?.deleteIds, [9]);
  assert.deepEqual(
    parseCommentState(plan?.body ?? '', ORIGIN).map((l) => [l.moduleKey, l.done]),
    [['a', true], ['b', false]],
  );
});

test('no rewrite when the kept comment already has everything', () => {
  const body = renderComment([lesson('a')]);
  assert.equal(planCommentCleanup([{ id: 1, body }, { id: 2, body }], ORIGIN)?.body, null);
});

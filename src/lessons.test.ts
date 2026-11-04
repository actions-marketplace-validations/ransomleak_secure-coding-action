import assert from 'node:assert/strict';
import { test } from 'node:test';

import { acceptLessons } from './lessons.ts';

const ORIGIN = 'https://app.ransomleak.com';
const lesson = (n: number, url = `${ORIGIN}/l/${n}`, title = `T${n}`) => ({
  moduleKey: `m${n}`,
  title,
  launchUrl: url,
  done: false,
});

test('drops off-origin and malformed lessons', () => {
  const out = acceptLessons(
    [lesson(1), lesson(2, 'https://evil.example/l/2'), lesson(3, 'not a url'), { moduleKey: 'x' }, lesson(4, 'http://app.ransomleak.com/l/4')],
    ORIGIN,
  );
  assert.deepEqual(out.map((l) => l.moduleKey), ['m1']);
});

test('caps at 5 lessons and truncates titles', () => {
  const many = Array.from({ length: 9 }, (_, i) => lesson(i, undefined, 'x'.repeat(500)));
  const out = acceptLessons(many, ORIGIN);
  assert.equal(out.length, 5);
  assert.ok(out.every((l) => l.title.length === 120));
});

test('non-array input gives no lessons', () => {
  assert.deepEqual(acceptLessons({}, ORIGIN), []);
});

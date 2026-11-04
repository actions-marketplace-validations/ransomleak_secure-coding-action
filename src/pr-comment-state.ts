// KEEP IN SYNC with backend/src/secure-coding-jit/utils/pr-comment-state.util.ts in the scorm-controller repo.
// This Action is published standalone, so the comment renderer and parser are copied, not imported.
// Everything below the "verbatim copy" line must equal the backend file minus its first (import) line;
// src/pr-comment-state.test.ts compares them whenever the backend file is present.

/** Same as backend `sanitizeNoteField`. */
const sanitizeNoteField = (value: string): string => value.replace(/[`<>@\r\n]/g, ' ').slice(0, 200);

// --- verbatim copy ---

export interface CommentLesson {
  moduleKey: string;
  title: string;
  launchUrl: string;
  done: boolean;
  completedAt?: string;
}

/** Most lessons shown in one pull request comment. */
export const MAX_COMMENT_LESSONS = 5;

/**
 * Where the comment is posted. Both render the same Markdown text; the flavour only names
 * the hidden markers, so one provider's parser never claims the other's comment.
 * Azure DevOps: HTML-comment markers are assumed to survive PR threads (Task 10 must confirm;
 * if they don't, state moves to thread `properties`).
 */
export type MarkdownFlavor = 'github' | 'azure';
export interface CommentRenderOptions {
  markdownFlavor: MarkdownFlavor;
}
const DEFAULT_FLAVOR: MarkdownFlavor = 'github';

/** Identifies the single RansomLeak comment on a pull request, per flavour. */
export const commentMarker = (flavor: MarkdownFlavor): string => `<!-- ransomleak:${flavor}:comment -->`;
/** Identifies the App's single comment on a GitHub pull request. */
export const GITHUB_COMMENT_MARKER = commentMarker('github');

const KEY_CHARS = /[^A-Za-z0-9_.-]/g;
/**
 * Done lines show a readable UTC date; the exact ISO stamp rides in the marker's optional
 * last field. Old comments carried the ISO stamp visibly (group 3), still parsed.
 * Text first, marker last: a line that starts with `<!--` is an HTML block in
 * GitHub Markdown, and the link after it would not render.
 */
const lineRegex = (flavor: MarkdownFlavor): RegExp =>
  new RegExp(
    `^- (?:⬜|✅) \\[([^\\]\\n]*)\\]\\((https?:\\/\\/[^\\s)]+)\\)(?: · completed via this link (?:on \\d{1,2} [A-Z][a-z]{2} \\d{4}|(\\S+)))? <!-- ransomleak:${flavor}:lesson:([A-Za-z0-9_.-]+):(open|done)(?::(\\S+?))? -->$`,
  );
const LINES: Record<MarkdownFlavor, RegExp> = { github: lineRegex('github'), azure: lineRegex('azure') };

export const ABOUT_URL = 'https://docs.ransomleak.com/integrations/github/';
/** The "About this app" link per flavour. The azure-devops page is created in Task 10. */
export const ABOUT_URLS: Record<MarkdownFlavor, string> = {
  github: ABOUT_URL,
  azure: 'https://docs.ransomleak.com/integrations/azure-devops/',
};

/** The one canonical key form used by merge, render and parse. */
export const normalizeLessonKey = (key: string): string => key.replace(KEY_CHARS, '-');
const marker = (flavor: MarkdownFlavor, key: string, done: boolean, stamp?: string): string =>
  `<!-- ransomleak:${flavor}:lesson:${normalizeLessonKey(key)}:${done ? `done${stamp ? `:${stamp}` : ''}` : 'open'} -->`;

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** `3 Nov 2026`, in UTC. */
const readableDate = (iso: string): string => {
  const d = new Date(iso);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
};

const ISO_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
/** Valid ISO-8601 timestamp or undefined. */
const validStamp = (value: string | undefined): string | undefined =>
  typeof value === 'string' && ISO_TS.test(value) && !Number.isNaN(Date.parse(value)) ? value : undefined;

const originOf = (url: string): string | null => {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
};

/** Whether a new lesson would be listed: there is a free slot, or a done lesson to evict. */
export const commentHasRoom = (lessons: CommentLesson[]): boolean =>
  lessons.length < MAX_COMMENT_LESSONS || lessons.some((l) => l.done);

/**
 * At most 5 lessons: evict the oldest done first. Open lessons are never evicted,
 * so with all of them open the newest entry, the last one, waits and isn't added.
 */
export function capLessons(lessons: CommentLesson[]): CommentLesson[] {
  const out = [...lessons];
  while (out.length > MAX_COMMENT_LESSONS) {
    const i = out.findIndex((l) => l.done);
    out.splice(i >= 0 ? i : out.length - 1, 1);
  }
  return out;
}

const safeTitle = (title: string): string => sanitizeNoteField(title).replace(/[[\]]/g, ' ').trim();
const safeUrl = (url: string): string =>
  /^https?:\/\//i.test(url)
    ? url.replace(/[\s()<>`]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`)
    : '';

/** Read lessons back from the hidden per-lesson markers. Malformed lines are skipped, never thrown on. */
export function parseCommentState(
  body: string,
  allowedOrigin?: string,
  opts: CommentRenderOptions = { markdownFlavor: DEFAULT_FLAVOR },
): CommentLesson[] {
  if (typeof body !== 'string') return [];
  const lessons: CommentLesson[] = [];
  const allowed = allowedOrigin === undefined ? undefined : originOf(allowedOrigin);
  for (const line of body.split(/\r?\n/)) {
    const m = LINES[opts.markdownFlavor].exec(line.trim());
    if (!m) continue;
    if (allowed !== undefined && (!allowed || originOf(m[2]) !== allowed)) continue;
    const done = m[5] === 'done';
    const stampText = m[6] ?? m[3];
    const lesson: CommentLesson = { moduleKey: m[4], title: m[1], launchUrl: m[2], done };
    const stamp = validStamp(stampText);
    if (done && stamp) lesson.completedAt = stamp;
    lessons.push(lesson);
  }
  return lessons;
}

export function renderComment(
  lessons: CommentLesson[],
  opts: CommentRenderOptions = { markdownFlavor: DEFAULT_FLAVOR },
): string {
  const flavor = opts.markdownFlavor;
  const shown = capLessons(lessons);
  const lines = [
    '**Security training for this pull request**',
    '',
    shown.length === 1
      ? 'Security scanning reported this type of issue on this pull request. This 5-10 minute lesson covers it:'
      : 'Security scanning reported these types of issues on this pull request. These 5-10 minute lessons cover them:',
    '',
  ];
  for (const l of shown) {
    const link = `[${safeTitle(l.title)}](${safeUrl(l.launchUrl)})`;
    const stamp = validStamp(l.completedAt);
    lines.push(
      l.done
        ? `- ✅ ${link}${stamp ? ` · completed via this link on ${readableDate(stamp)}` : ''} ${marker(flavor, l.moduleKey, true, stamp)}`
        : `- ⬜ ${link} ${marker(flavor, l.moduleKey, false)}`,
    );
  }
  lines.push('', `Provided free by RansomLeak. [About this app](${ABOUT_URLS[flavor]})`, '', commentMarker(flavor));
  return lines.join('\n') + '\n';
}

/** Dedup by moduleKey (done is sticky), cap at 5 (see capLessons). */
export function mergeLesson(existing: CommentLesson[], next: CommentLesson): CommentLesson[] {
  const merged = existing.map((l) => ({ ...l, moduleKey: normalizeLessonKey(l.moduleKey) }));
  const key = normalizeLessonKey(next.moduleKey);
  const idx = merged.findIndex((l) => l.moduleKey === key);
  if (idx >= 0) {
    if (merged[idx].done) return capLessons(merged);
    merged[idx] = { ...next, moduleKey: key };
    if (!next.done) delete merged[idx].completedAt;
  } else {
    merged.push({ ...next, moduleKey: key });
  }
  return capLessons(merged);
}

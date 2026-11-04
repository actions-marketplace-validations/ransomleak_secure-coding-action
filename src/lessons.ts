import { type CommentLesson, MAX_COMMENT_LESSONS } from './pr-comment-state.ts';

const MAX_TITLE_LENGTH = 120;

const isLesson = (v: unknown): v is CommentLesson => {
  const l = v as Partial<CommentLesson> | null;
  return (
    typeof l === 'object' &&
    l !== null &&
    typeof l.moduleKey === 'string' &&
    typeof l.title === 'string' &&
    typeof l.launchUrl === 'string' &&
    typeof l.done === 'boolean'
  );
};

const originOf = (url: string): string | null => {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
};

/** Keeps only well-formed lessons whose link is on the API origin, at most 5, with a capped title. */
export function acceptLessons(raw: unknown, apiOrigin: string): CommentLesson[] {
  const allowed = originOf(apiOrigin);
  if (!allowed || !Array.isArray(raw)) return [];
  return raw
    .filter(isLesson)
    .filter((l) => originOf(l.launchUrl) === allowed)
    .slice(0, MAX_COMMENT_LESSONS)
    .map((l) => ({ ...l, title: l.title.slice(0, MAX_TITLE_LENGTH) }));
}

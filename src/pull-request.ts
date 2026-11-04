import { mergeLesson, parseCommentState, renderComment } from './pr-comment-state.ts';

interface PullRepos {
  [key: string]: unknown;
  head?: { repo?: { full_name?: unknown } | null } | null;
  base?: { repo?: { full_name?: unknown } | null } | null;
}

/**
 * True for a fork, including one whose head repository was deleted. A same-repo
 * pull request stays eligible even when the repository is itself a fork.
 */
export const isFromFork = (pull: PullRepos): boolean => pull.head?.repo?.full_name !== pull.base?.repo?.full_name;

export interface MarkerComment {
  id: number;
  body?: string;
}

export interface CommentCleanup {
  keepId: number;
  /** The merged body, or null when the kept comment already says it. */
  body: string | null;
  deleteIds: number[];
}

/** Concurrent runs can each create a comment. Keep the lowest id and fold the others into it. */
export function planCommentCleanup(comments: MarkerComment[], origin: string): CommentCleanup | null {
  if (comments.length < 2) return null;
  const [keep, ...extras] = [...comments].sort((a, b) => a.id - b.id);
  let merged = parseCommentState(keep.body ?? '', origin);
  for (const extra of extras) {
    for (const lesson of parseCommentState(extra.body ?? '', origin)) merged = mergeLesson(merged, lesson);
  }
  const body = renderComment(merged);
  return { keepId: keep.id, body: body === keep.body ? null : body, deleteIds: extras.map((c) => c.id) };
}

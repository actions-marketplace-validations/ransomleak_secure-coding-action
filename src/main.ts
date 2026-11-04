import { stat, readFile } from 'node:fs/promises';

import * as core from '@actions/core';
import * as github from '@actions/github';

import { acceptLessons } from './lessons.ts';
import {
  type CommentLesson,
  GITHUB_COMMENT_MARKER,
  mergeLesson,
  parseCommentState,
  renderComment,
} from './pr-comment-state.ts';
import { isFromFork, type MarkerComment, planCommentCleanup } from './pull-request.ts';
import { extractFindings, SarifError } from './sarif.ts';

const AUDIENCE = 'ransomleak-jit';
/** Fixed at build time by esbuild `define`. The OIDC token must never follow a workflow-controlled value. */
declare const __API_ORIGIN__: string;
const TIMEOUT_MS = 10_000;
const MAX_SARIF_BYTES = 50 * 1024 * 1024;
const ACTIONS_BOT = 'github-actions[bot]';

/** Nothing here may log a secret, token, path, message or snippet, so errors are described by class and status only. */
function describe(error: unknown): string {
  if (error instanceof SarifError) return error.message;
  const status = (error as { status?: unknown } | null)?.status;
  const name = error instanceof Error ? error.name : 'error';
  return typeof status === 'number' ? `${name} (HTTP ${status})` : name;
}

function withTimeout<T>(work: Promise<T>, label: string): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out`)), TIMEOUT_MS);
  });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

async function run(): Promise<void> {
  const { context } = github;
  if (context.eventName !== 'pull_request') {
    core.notice('RansomLeak lessons run on pull_request events only. Skipping.');
    return;
  }
  const pull = context.payload.pull_request;
  if (!pull) {
    core.warning('No pull request in the event payload. Skipping.');
    return;
  }
  if (isFromFork(pull)) {
    core.notice('Pull requests from forks get a read-only token and no OIDC token. Skipping.');
    return;
  }
  if (pull.user?.type === 'Bot') {
    core.notice('The pull request was opened by a bot. Skipping.');
    return;
  }
  const pullNumber = Number(pull.number);
  if (!Number.isInteger(pullNumber) || pullNumber < 1) {
    core.warning('Could not read the pull request number. Skipping.');
    return;
  }

  const sarifPath = core.getInput('sarif', { required: true });
  let findings;
  try {
    const info = await stat(sarifPath);
    if (info.size > MAX_SARIF_BYTES) {
      core.warning('The SARIF file is larger than 50MB. Skipping.');
      return;
    }
    findings = extractFindings(await readFile(sarifPath, 'utf8'));
  } catch (error) {
    core.warning(`Could not read the SARIF file: ${error instanceof SarifError ? error.message : 'unreadable'}.`);
    return;
  }
  if (findings.length === 0) {
    core.info('No findings with a CWE, CVE or GHSA identifier or from a secrets scanner. Nothing to send.');
    return;
  }

  let idToken: string;
  try {
    idToken = await withTimeout(core.getIDToken(AUDIENCE), 'OIDC token request');
  } catch {
    core.warning('Could not get an OIDC token. Add `id-token: write` to the job permissions.');
    return;
  }

  const origin = __API_ORIGIN__;
  let postedByApp = false;
  let lessons: CommentLesson[] = [];
  try {
    const res = await fetch(`${origin}/api/github-jit/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
      body: JSON.stringify({ pullNumber, findings }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) {
      core.warning(`RansomLeak returned HTTP ${res.status}. No lessons this run.`);
      return;
    }
    const data = (await res.json()) as { postedByApp?: unknown; lessons?: unknown };
    postedByApp = data.postedByApp === true;
    lessons = acceptLessons(data.lessons, origin);
  } catch (error) {
    core.warning(`Could not reach RansomLeak: ${describe(error)}.`);
    return;
  }

  if (postedByApp) {
    core.info('The RansomLeak GitHub App already commented on this pull request.');
    return;
  }
  if (lessons.length === 0) {
    core.info('No matching lessons for these findings.');
    return;
  }
  await withTimeout(postComment(lessons, pullNumber, origin), 'Comment update');
}

async function postComment(
  lessons: CommentLesson[],
  pullNumber: number,
  origin: string,
): Promise<void> {
  const { owner, repo } = github.context.repo;
  const octokit = github.getOctokit(core.getInput('github-token'));
  const listMine = async (): Promise<MarkerComment[]> => {
    const found: MarkerComment[] = [];
    const pages = octokit.paginate.iterator(octokit.rest.issues.listComments, {
      owner,
      repo,
      issue_number: pullNumber,
      per_page: 100,
    });
    for await (const { data } of pages) {
      for (const c of data) {
        // A marker in anyone else's comment is ignored.
        if ((c.body ?? '').includes(GITHUB_COMMENT_MARKER) && c.user?.login === ACTIONS_BOT) {
          found.push({ id: c.id, body: c.body });
        }
      }
    }
    return found.sort((a, b) => a.id - b.id);
  };
  try {
    const mine = (await listMine())[0];
    let merged = mine ? parseCommentState(mine.body ?? '', origin) : [];
    for (const lesson of lessons) merged = mergeLesson(merged, lesson);
    const body = renderComment(merged);

    if (mine) {
      if (mine.body === body) {
        core.info('The lesson comment is already up to date.');
      } else {
        await octokit.rest.issues.updateComment({ owner, repo, comment_id: mine.id, body });
      }
    } else {
      await octokit.rest.issues.createComment({ owner, repo, issue_number: pullNumber, body });
    }
    core.info('Posted the secure-coding lesson links.');
  } catch (error) {
    const status = (error as { status?: number }).status;
    core.warning(
      status === 403 || status === 404
        ? 'Could not post the comment. Add `pull-requests: write` to the job permissions.'
        : `Could not post the comment: ${describe(error)}.`,
    );
    return;
  }

  // Runs on the same pull request can race. The list only returns this bot's comments, so only those get deleted.
  try {
    const cleanup = planCommentCleanup(await listMine(), origin);
    if (!cleanup) return;
    if (cleanup.body !== null) {
      await octokit.rest.issues.updateComment({ owner, repo, comment_id: cleanup.keepId, body: cleanup.body });
    }
    for (const id of cleanup.deleteIds) {
      await octokit.rest.issues.deleteComment({ owner, repo, comment_id: id }).catch((error: { status?: number }) => {
        // A run racing this one got there first.
        if (error.status !== 404) throw error;
      });
    }
  } catch (error) {
    core.warning(`Could not merge duplicate lesson comments: ${describe(error)}.`);
  }
}

async function main(): Promise<void> {
  try {
    await run();
  } catch (error) {
    core.warning(`RansomLeak lessons skipped: ${describe(error)}.`);
  }
  // Never fail the workflow, and never wait on a stray handle.
  process.exit(0);
}

void main();

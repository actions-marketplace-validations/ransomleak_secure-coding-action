import type { ActionFinding } from './sarif.ts';
import type { SonarConfig, SonarHotspot } from './sonar-client.ts';
import {
  fetchHotspots,
  fetchNewVulnerabilityCount,
  fetchPrIssues,
  fetchPullRequestCommit,
  fetchRuleStandards,
  isSonarCloud,
  parseReportTask,
  SonarError,
  waitForAnalysis,
} from './sonar-client.ts';
import { ruleKeysOf, sonarFindings } from './sonar-findings.ts';

export const SONAR_TOKEN_MESSAGE =
  'RansomLeak: could not read issues from SonarQube. The token needs Browse permission on the project (use a user token on Server, or a personal or scoped organization token on SonarQube Cloud). No lessons were posted.';
export const SONAR_CLOUD_NO_PR_MESSAGE =
  'RansomLeak: SonarQube Cloud has not analysed this pull request yet. Check that Automatic Analysis or your CI scan is enabled and has run, or raise sonar-wait-timeout. No lessons were posted.';
export const SONAR_NO_PR_MESSAGE =
  'RansomLeak: SonarQube has no pull request analysis for this pull request. Community Build does not analyse pull requests. Use the sarif input instead. No lessons were posted.';

export interface SonarSourceOptions {
  includeHotspots: boolean;
  waitTimeoutSec: number;
  /** Contents of the scanner's `report-task.txt`, or null when none was found. */
  reportTask: string | null;
  /** Head commit of the pull request; without a report-task.txt the Action waits for an analysis of it. */
  headSha?: string | null;
  log: (line: string) => void;
}

export type SonarResult = { findings: ActionFinding[] } | { skip: string };

async function pollForHeadCommit(cfg: SonarConfig, headSha: string, timeoutSec: number): Promise<number | null> {
  const sleep = cfg.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const deadline = Date.now() + timeoutSec * 1000;
  for (;;) {
    const sha = await fetchPullRequestCommit(cfg);
    if (sha === headSha) return fetchNewVulnerabilityCount(cfg);
    if (Date.now() + 5_000 > deadline) {
      throw sha === null
        ? new SonarError('no-pr', 'Sonar has no analysis for this pull request')
        : new SonarError('stale', 'the latest analysis is for an older commit');
    }
    await sleep(5_000);
  }
}

async function pollForPullRequest(cfg: SonarConfig, timeoutSec: number): Promise<number | null> {
  const sleep = cfg.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const deadline = Date.now() + timeoutSec * 1000;
  for (;;) {
    try {
      return await fetchNewVulnerabilityCount(cfg);
    } catch (error) {
      if (!(error instanceof SonarError) || error.kind !== 'no-pr' || Date.now() + 5_000 > deadline) throw error;
    }
    await sleep(5_000);
  }
}

/** Never throws: every failure becomes a one-line reason to skip. */
export async function readSonarFindings(cfg: SonarConfig, opts: SonarSourceOptions): Promise<SonarResult> {
  try {
    const taskId = opts.reportTask === null ? null : parseReportTask(opts.reportTask);
    if (taskId) {
      await waitForAnalysis(cfg, taskId, opts.waitTimeoutSec);
    } else {
      opts.log(
        isSonarCloud(cfg.hostUrl) && opts.headSha
          ? 'No SonarQube report-task.txt found, so the Action waits for an analysis of this commit.'
          : 'No SonarQube report-task.txt found, so the Action reads the latest analysis without waiting.',
      );
    }
    // Automatic Analysis leaves no report-task.txt and may finish after this job does, so on SonarQube
    // Cloud (which always analyses pull requests) keep asking until the pull request appears.
    const expectedNew =
      taskId || !isSonarCloud(cfg.hostUrl)
        ? await fetchNewVulnerabilityCount(cfg)
        : opts.headSha
          ? await pollForHeadCommit(cfg, opts.headSha, opts.waitTimeoutSec)
          : await pollForPullRequest(cfg, opts.waitTimeoutSec);
    const issues = await fetchPrIssues(cfg, expectedNew);
    const hotspots: SonarHotspot[] = opts.includeHotspots ? await fetchHotspots(cfg) : [];
    const standards = await fetchRuleStandards(cfg, ruleKeysOf(issues, hotspots));
    return { findings: sonarFindings(issues, hotspots, standards) };
  } catch (error) {
    if (!(error instanceof SonarError)) {
      return {
        skip: `RansomLeak: could not read SonarQube results (${error instanceof Error ? error.name : 'error'}). No lessons were posted.`,
      };
    }
    switch (error.kind) {
      case 'auth':
        return { skip: SONAR_TOKEN_MESSAGE };
      case 'no-pr':
        return { skip: isSonarCloud(cfg.hostUrl) ? SONAR_CLOUD_NO_PR_MESSAGE : SONAR_NO_PR_MESSAGE };
      case 'timeout':
        return {
          skip: `RansomLeak: the SonarQube analysis did not finish within ${opts.waitTimeoutSec} seconds. No lessons were posted.`,
        };
      case 'stale':
        return {
          skip: `RansomLeak: SonarQube had not analysed the latest commit within ${opts.waitTimeoutSec} seconds, so no lessons were posted or changed. Raise sonar-wait-timeout or rerun the job.`,
        };
      case 'mismatch':
        return {
          skip: 'RansomLeak: the SonarQube analysis is for a different pull request. No lessons were posted.',
        };
      default:
        return {
          skip: `RansomLeak: could not read SonarQube results: ${error.message}. No lessons were posted.`,
        };
    }
  }
}

/**
 * Li Code Review - GitHub Action Entry Point
 * Analyzes PR diffs and posts review comments.
 */

const core = require('@actions/core');
const github = require('@actions/github');
const { analyzeDiff, formatReviewComment, generateSummary } = require('./analyzer');

async function parseDiff(diffText) {
  const files = [];
  const fileParts = diffText.split(/^diff --git /m).filter(Boolean);

  for (const part of fileParts) {
    const filenameMatch = part.match(/b\/(.+?)(?:\n|$)/);
    if (!filenameMatch) continue;

    const filepath = filenameMatch[1];

    // Skip binary files, lockfiles, etc
    if (/\.(lock|min\.|map|woff|ttf|png|jpg|gif|svg|ico|pdf)/.test(filepath)) continue;
    if (/(?:node_modules|vendor|dist|build|\.next)\//.test(filepath)) continue;
    if (/package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum/.test(filepath)) continue;

    const changedLines = [];
    let currentLine = 0;
    const contentLines = [];

    const lines = part.split('\n');
    for (const line of lines) {
      const hunkMatch = line.match(/^@@\s*-\d+(?:,\d+)?\s*\+(\d+)(?:,\d+)?\s*@@/);
      if (hunkMatch) {
        currentLine = parseInt(hunkMatch[1], 10);
        continue;
      }

      if (line.startsWith('+') && !line.startsWith('+++')) {
        changedLines.push(currentLine);
        contentLines[currentLine - 1] = line.substring(1);
        currentLine++;
      } else if (line.startsWith('-') && !line.startsWith('---')) {
        // deleted line, don't increment
      } else if (!line.startsWith('\\')) {
        contentLines[currentLine - 1] = line.startsWith(' ') ? line.substring(1) : line;
        currentLine++;
      }
    }

    if (contentLines.length > 0) {
      files.push({
        filepath,
        content: contentLines.join('\n'),
        changedLines
      });
    }
  }

  return files;
}

async function run() {
  try {
    const token = core.getInput('github-token') || process.env.GITHUB_TOKEN;
    const severity = core.getInput('severity') || 'warning';
    const maxComments = parseInt(core.getInput('max-comments') || '20', 10);

    if (!token) {
      core.setFailed('GitHub token is required');
      return;
    }

    const octokit = github.getOctokit(token);
    const context = github.context;

    if (!context.payload.pull_request) {
      core.info('Not a pull request event. Skipping.');
      return;
    }

    const { owner, repo } = context.repo;
    const pull_number = context.payload.pull_request.number;

    core.info(`Analyzing PR #${pull_number} in ${owner}/${repo}...`);

    // Get the PR diff
    const { data: diff } = await octokit.rest.pulls.get({
      owner,
      repo,
      pull_number,
      mediaType: { format: 'diff' }
    });

    // Parse diff into files
    const files = await parseDiff(diff);
    core.info(`Found ${files.length} files to analyze`);

    // Analyze
    const results = analyzeDiff(files, severity);

    // Count issues
    let totalIssues = 0;
    for (const r of results) totalIssues += r.issues.length;

    core.info(`Found ${totalIssues} issues`);

    // Post review comments (up to maxComments)
    const comments = [];
    for (const result of results) {
      for (const issue of result.issues) {
        if (comments.length >= maxComments) break;
        comments.push({
          path: result.filepath,
          line: issue.line,
          body: formatReviewComment(issue)
        });
      }
    }

    if (comments.length > 0) {
      try {
        await octokit.rest.pulls.createReview({
          owner,
          repo,
          pull_number,
          event: totalIssues > 0 ? 'COMMENT' : 'APPROVE',
          body: generateSummary(results),
          comments
        });
        core.info(`Posted review with ${comments.length} comments`);
      } catch (reviewError) {
        // If review comments fail (e.g., line not in diff), post as a regular comment
        core.warning(`Could not post inline comments: ${reviewError.message}`);
        await octokit.rest.issues.createComment({
          owner,
          repo,
          issue_number: pull_number,
          body: generateSummary(results)
        });
      }
    } else {
      // Post summary comment even if no issues
      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: pull_number,
        body: generateSummary(results)
      });
    }

    // Set outputs
    core.setOutput('issues-found', totalIssues.toString());
    core.setOutput('summary', generateSummary(results));

    if (results.some(r => r.issues.some(i => i.severity === 'error'))) {
      core.warning(`Found ${totalIssues} issues including errors. Review recommended.`);
    }

  } catch (error) {
    core.setFailed(`Li Code Review failed: ${error.message}`);
  }
}

run();

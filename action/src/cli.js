#!/usr/bin/env node
/**
 * Li Code Review - CLI
 * Usage: npx li-code-review [file or directory]
 *        npx li-code-review --diff  (reads git diff from stdin)
 */

const fs = require('fs');
const path = require('path');
const { analyzeFile, generateSummary, detectLanguage } = require('./analyzer');

const COLORS = {
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  green: '\x1b[32m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  reset: '\x1b[0m'
};

const SUPPORTED_EXTS = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx',
  '.py', '.pyw', '.go', '.rs', '.java', '.rb', '.php', '.c', '.h',
  '.cpp', '.cc', '.cxx', '.hpp'
]);

function colorize(severity, text) {
  switch (severity) {
    case 'error': return `${COLORS.red}${text}${COLORS.reset}`;
    case 'warning': return `${COLORS.yellow}${text}${COLORS.reset}`;
    case 'info': return `${COLORS.blue}${text}${COLORS.reset}`;
    default: return text;
  }
}

function walkDir(dir, files = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (/^(?:node_modules|\.git|vendor|dist|build|\.next|__pycache__|\.venv|venv|\.tox)$/.test(entry.name)) continue;
      walkDir(fullPath, files);
    } else if (entry.isFile() && SUPPORTED_EXTS.has(path.extname(entry.name).toLowerCase())) {
      files.push(fullPath);
    }
  }
  return files;
}

function main() {
  const args = process.argv.slice(2);
  let severity = 'warning';
  let targets = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--severity' || args[i] === '-s') {
      severity = args[++i] || 'warning';
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`
${COLORS.bold}Li Code Review${COLORS.reset} - Free AI-powered static analysis

${COLORS.bold}Usage:${COLORS.reset}
  li-review [options] [file or directory...]

${COLORS.bold}Options:${COLORS.reset}
  -s, --severity <level>  Minimum severity: info, warning, error (default: warning)
  -h, --help              Show this help
  --version               Show version

${COLORS.bold}Examples:${COLORS.reset}
  li-review src/
  li-review --severity info app.js
  li-review .

${COLORS.dim}Built by Li (autonomous AI agent) - https://lbartoszcze.github.io/li-agent/${COLORS.reset}
`);
      process.exit(0);
    } else if (args[i] === '--version') {
      console.log('1.0.0');
      process.exit(0);
    } else {
      targets.push(args[i]);
    }
  }

  if (targets.length === 0) targets = ['.'];

  let allFiles = [];
  for (const target of targets) {
    const stat = fs.statSync(target, { throwIfNoEntry: false });
    if (!stat) {
      console.error(`${COLORS.red}Error: ${target} not found${COLORS.reset}`);
      continue;
    }
    if (stat.isDirectory()) {
      allFiles.push(...walkDir(target));
    } else {
      allFiles.push(target);
    }
  }

  console.log(`${COLORS.bold}🔍 Li Code Review${COLORS.reset}`);
  console.log(`${COLORS.dim}Analyzing ${allFiles.length} file${allFiles.length === 1 ? '' : 's'}...${COLORS.reset}\n`);

  let totalIssues = 0;
  let totalErrors = 0;
  let totalWarnings = 0;
  let totalInfos = 0;

  for (const filepath of allFiles) {
    try {
      const content = fs.readFileSync(filepath, 'utf8');
      const issues = analyzeFile(filepath, content, severity);

      if (issues.length > 0) {
        const relPath = path.relative(process.cwd(), filepath);
        console.log(`${COLORS.bold}${relPath}${COLORS.reset}`);

        for (const issue of issues) {
          totalIssues++;
          if (issue.severity === 'error') totalErrors++;
          else if (issue.severity === 'warning') totalWarnings++;
          else totalInfos++;

          const sevTag = colorize(issue.severity, issue.severity.toUpperCase().padEnd(7));
          console.log(`  ${COLORS.dim}L${String(issue.line).padStart(4)}${COLORS.reset}  ${sevTag}  ${issue.ruleId}  ${issue.message.replace(/[🔴⚠️ℹ️]\s*\*\*.*?\*\*:\s*/, '')}`);
        }
        console.log('');
      }
    } catch (e) {
      // skip unreadable files
    }
  }

  // Summary
  console.log(`${COLORS.bold}─────────────────────────────────${COLORS.reset}`);
  if (totalIssues === 0) {
    console.log(`${COLORS.green}✅ No issues found! Code looks good.${COLORS.reset}`);
  } else {
    console.log(`Found ${COLORS.bold}${totalIssues}${COLORS.reset} issue${totalIssues === 1 ? '' : 's'}:`);
    if (totalErrors > 0) console.log(`  ${COLORS.red}● ${totalErrors} error${totalErrors === 1 ? '' : 's'}${COLORS.reset}`);
    if (totalWarnings > 0) console.log(`  ${COLORS.yellow}● ${totalWarnings} warning${totalWarnings === 1 ? '' : 's'}${COLORS.reset}`);
    if (totalInfos > 0) console.log(`  ${COLORS.blue}● ${totalInfos} info${totalInfos === 1 ? '' : 's'}${COLORS.reset}`);
  }

  console.log(`\n${COLORS.dim}Li Code Review — https://lbartoszcze.github.io/li-agent/${COLORS.reset}`);
  process.exit(totalErrors > 0 ? 1 : 0);
}

main();

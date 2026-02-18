/**
 * Li Code Review - Static Analysis Engine
 * Catches security issues, bugs, performance problems, and style issues
 * across JavaScript, TypeScript, Python, Go, Rust, Java, and more.
 *
 * Built by Li (an autonomous AI agent) - https://lbartoszcze.github.io/li-agent/
 */

const SEVERITY = { info: 0, warning: 1, error: 2 };

// ============================================================================
// RULE DEFINITIONS
// ============================================================================

const rules = [
  // --- SECURITY ---
  {
    id: 'SEC001',
    name: 'SQL Injection Risk',
    severity: 'error',
    languages: ['js', 'ts', 'py', 'java', 'go', 'rb', 'php'],
    pattern: /(?:query|execute|exec|raw)\s*\(\s*(?:`[^`]*\$\{|f['"][^'"]*\{|['"].*?\+\s*(?:req|request|params|input|user|args)|['"].*?%s|['"].*?\?\s*%)/gi,
    message: '🔴 **SQL Injection Risk**: String interpolation in SQL query. Use parameterized queries instead.',
    suggestion: 'Use parameterized queries: `db.query("SELECT * FROM users WHERE id = ?", [userId])`'
  },
  {
    id: 'SEC002',
    name: 'eval() Usage',
    severity: 'error',
    languages: ['js', 'ts', 'py'],
    pattern: /\beval\s*\(/g,
    message: '🔴 **Dangerous eval()**: `eval()` executes arbitrary code and is a major security risk.',
    suggestion: 'Use `JSON.parse()` for JSON, `new Function()` if absolutely necessary, or refactor to avoid dynamic code execution.'
  },
  {
    id: 'SEC003',
    name: 'Hardcoded Secrets',
    severity: 'error',
    languages: ['*'],
    pattern: /(?:password|secret|api_key|apikey|api_secret|access_token|auth_token|private_key)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    message: '🔴 **Hardcoded Secret**: Credentials should never be hardcoded. Use environment variables.',
    suggestion: 'Use `process.env.SECRET_NAME` or a secrets manager like AWS Secrets Manager, Vault, etc.'
  },
  {
    id: 'SEC004',
    name: 'Path Traversal',
    severity: 'error',
    languages: ['js', 'ts', 'py', 'go', 'java', 'rb', 'php'],
    pattern: /(?:readFile|readFileSync|open|fopen|os\.path\.join|filepath\.Join)\s*\([^)]*(?:req\.|request\.|params\.|input|user_input|args)/gi,
    message: '🔴 **Path Traversal Risk**: User input used in file path without sanitization.',
    suggestion: 'Validate and sanitize file paths. Use `path.resolve()` and check the result stays within the expected directory.'
  },
  {
    id: 'SEC005',
    name: 'XSS via innerHTML',
    severity: 'error',
    languages: ['js', 'ts'],
    pattern: /\.innerHTML\s*=\s*(?!['"`]<)/g,
    message: '🔴 **XSS Risk**: Setting `innerHTML` with dynamic content can lead to cross-site scripting.',
    suggestion: 'Use `textContent` for text, or sanitize HTML with DOMPurify before using innerHTML.'
  },
  {
    id: 'SEC006',
    name: 'Command Injection',
    severity: 'error',
    languages: ['js', 'ts', 'py', 'rb', 'php'],
    pattern: /(?:exec|spawn|system|popen|subprocess\.call|subprocess\.run|os\.system)\s*\([^)]*(?:\+|`|\$\{|\.format|%s|f['"])/gi,
    message: '🔴 **Command Injection Risk**: User input in shell command without proper escaping.',
    suggestion: 'Use array-form of exec (e.g., `execFile`) or properly escape shell arguments.'
  },
  {
    id: 'SEC007',
    name: 'Insecure Randomness',
    severity: 'warning',
    languages: ['js', 'ts'],
    pattern: /Math\.random\s*\(\)/g,
    message: '⚠️ **Insecure Randomness**: `Math.random()` is not cryptographically secure.',
    suggestion: 'For security-sensitive operations, use `crypto.randomBytes()` or `crypto.getRandomValues()`.',
    contextFilter: (line) => /(?:token|secret|password|key|auth|session|nonce|salt|hash|crypto)/i.test(line)
  },
  {
    id: 'SEC008',
    name: 'Disabled SSL Verification',
    severity: 'error',
    languages: ['py', 'js', 'ts', 'go', 'java', 'rb'],
    pattern: /(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|VERIFY_NONE|ssl_verify.*false)/gi,
    message: '🔴 **SSL Verification Disabled**: This makes connections vulnerable to man-in-the-middle attacks.',
    suggestion: 'Enable SSL verification in production. Only disable for local development if absolutely necessary.'
  },

  // --- BUGS ---
  {
    id: 'BUG001',
    name: 'Loose Equality',
    severity: 'warning',
    languages: ['js', 'ts'],
    pattern: /[^=!<>]==[^=]/g,
    message: '⚠️ **Loose Equality**: `==` performs type coercion. Use `===` for strict comparison.',
    suggestion: 'Replace `==` with `===` and `!=` with `!==` to avoid unexpected type coercion.',
    contextFilter: (line) => !/['"`].*==.*['"`]/.test(line) // skip inside strings
  },
  {
    id: 'BUG002',
    name: 'Floating Point Comparison',
    severity: 'warning',
    languages: ['js', 'ts', 'py', 'java', 'go', 'c', 'cpp'],
    pattern: /(?:0\.\d+|parseFloat|float\()\s*===?\s*(?:0\.\d+|parseFloat|float\()/g,
    message: '⚠️ **Floating Point Comparison**: Direct comparison of floating-point numbers is unreliable.',
    suggestion: 'Use `Math.abs(a - b) < Number.EPSILON` or a tolerance-based comparison.'
  },
  {
    id: 'BUG003',
    name: 'Missing await',
    severity: 'warning',
    languages: ['js', 'ts'],
    pattern: /(?:^|\s)(?:const|let|var)\s+\w+\s*=\s*(?:\w+\.(?:find|save|create|update|delete|fetch|get|post|put|patch|remove|insert|query)\s*\()/gm,
    message: '⚠️ **Possible Missing await**: This async operation may need `await` to work correctly.',
    suggestion: 'If this function returns a Promise, add `await` to ensure proper execution order.',
    contextFilter: (line) => !/await/.test(line)
  },
  {
    id: 'BUG004',
    name: 'Empty Catch Block',
    severity: 'warning',
    languages: ['js', 'ts', 'java', 'py'],
    pattern: /catch\s*(?:\([^)]*\))?\s*\{\s*\}/g,
    message: '⚠️ **Empty Catch Block**: Silently swallowing errors makes debugging impossible.',
    suggestion: 'At minimum, log the error: `catch (e) { console.error(e); }` or handle it properly.'
  },
  {
    id: 'BUG005',
    name: 'Console.log in Production',
    severity: 'info',
    languages: ['js', 'ts'],
    pattern: /console\.log\s*\(/g,
    message: 'ℹ️ **Console.log**: Consider removing console.log from production code.',
    suggestion: 'Use a proper logger (winston, pino) or remove before deploying.',
    contextFilter: (line) => !/\/\/.*console|test|spec|debug/.test(line)
  },
  {
    id: 'BUG006',
    name: 'TODO/FIXME/HACK Comments',
    severity: 'info',
    languages: ['*'],
    pattern: /\/\/\s*(?:TODO|FIXME|HACK|XXX|BUG|WORKAROUND)[\s:]/gi,
    message: 'ℹ️ **Technical Debt**: Found a TODO/FIXME comment that should be tracked.',
    suggestion: 'Create a GitHub issue to track this technical debt item.'
  },

  // --- PERFORMANCE ---
  {
    id: 'PERF001',
    name: 'N+1 Query Pattern',
    severity: 'warning',
    languages: ['js', 'ts', 'py', 'rb', 'java'],
    pattern: /(?:for|forEach|map|\.each)\s*(?:\(|{)[\s\S]{0,100}(?:await|\.query|\.find|\.get|\.fetch|\.execute|\.select)/gm,
    message: '⚠️ **N+1 Query**: Database query inside a loop causes performance issues.',
    suggestion: 'Batch queries outside the loop, or use eager loading / JOINs.'
  },
  {
    id: 'PERF002',
    name: 'Synchronous I/O',
    severity: 'warning',
    languages: ['js', 'ts'],
    pattern: /(?:readFileSync|writeFileSync|mkdirSync|readdirSync|statSync|existsSync|appendFileSync|copyFileSync|renameSync|unlinkSync|rmdirSync)\s*\(/g,
    message: '⚠️ **Synchronous I/O**: Blocking I/O operations can freeze the event loop.',
    suggestion: 'Use async versions (e.g., `fs.promises.readFile`) to avoid blocking.',
    contextFilter: (line) => !/(?:config|setup|init|boot|build|script|cli|bin)/.test(line)
  },
  {
    id: 'PERF003',
    name: 'Unbounded Array Growth',
    severity: 'warning',
    languages: ['js', 'ts', 'py'],
    pattern: /while\s*\(true\)[\s\S]{0,200}\.push\s*\(/gm,
    message: '⚠️ **Unbounded Array Growth**: Array growing in infinite loop can cause memory exhaustion.',
    suggestion: 'Add a maximum size check or use a bounded data structure.'
  },
  {
    id: 'PERF004',
    name: 'Regex in Loop',
    severity: 'info',
    languages: ['js', 'ts', 'py', 'java'],
    pattern: /(?:for|while|forEach|map)\s*(?:\(|{)[\s\S]{0,50}new RegExp\(/gm,
    message: 'ℹ️ **Regex in Loop**: Creating regex inside a loop is inefficient.',
    suggestion: 'Compile the regex once outside the loop.'
  },

  // --- PYTHON SPECIFIC ---
  {
    id: 'PY001',
    name: 'Mutable Default Argument',
    severity: 'error',
    languages: ['py'],
    pattern: /def\s+\w+\s*\([^)]*(?:=\s*\[\]|=\s*\{\}|=\s*set\(\))/g,
    message: '🔴 **Mutable Default Argument**: Mutable default arguments are shared between calls.',
    suggestion: 'Use `None` as default and create the mutable object inside the function: `def f(x=None): x = x or []`'
  },
  {
    id: 'PY002',
    name: 'Bare Except',
    severity: 'warning',
    languages: ['py'],
    pattern: /except\s*:/g,
    message: '⚠️ **Bare Except**: Catches all exceptions including KeyboardInterrupt and SystemExit.',
    suggestion: 'Use `except Exception:` at minimum, or catch specific exceptions.'
  },
  {
    id: 'PY003',
    name: 'Assert in Production',
    severity: 'warning',
    languages: ['py'],
    pattern: /^assert\s+/gm,
    message: '⚠️ **Assert in Production**: Assert statements are stripped with `-O` flag.',
    suggestion: 'Use explicit `if not condition: raise ValueError()` for production validation.',
    contextFilter: (line, filepath) => !/test/.test(filepath)
  },

  // --- GO SPECIFIC ---
  {
    id: 'GO001',
    name: 'Unchecked Error',
    severity: 'warning',
    languages: ['go'],
    pattern: /[^,]\s*:?=\s*\w+\.\w+\([^)]*\)\s*$/gm,
    message: '⚠️ **Unchecked Error**: Go function may return an error that is not being checked.',
    suggestion: 'Check errors: `result, err := fn(); if err != nil { return err }`'
  },
  {
    id: 'GO002',
    name: 'Goroutine Leak',
    severity: 'warning',
    languages: ['go'],
    pattern: /go\s+func\s*\(/g,
    message: '⚠️ **Goroutine Leak Risk**: Anonymous goroutine without clear lifecycle management.',
    suggestion: 'Ensure goroutines have proper cancellation via context or done channels.'
  },

  // --- REACT/FRONTEND ---
  {
    id: 'REACT001',
    name: 'Missing Dependency Array',
    severity: 'warning',
    languages: ['js', 'ts', 'jsx', 'tsx'],
    pattern: /use(?:Effect|Callback|Memo)\s*\(\s*(?:\(\)|[^,]+),\s*\[\s*\]\s*\)/g,
    message: '⚠️ **Empty Dependency Array**: Hook with empty deps array runs only once. Verify this is intentional.',
    suggestion: 'Add all referenced variables to the dependency array, or add a comment explaining why it should only run once.'
  },
  {
    id: 'REACT002',
    name: 'State Update in Render',
    severity: 'error',
    languages: ['js', 'ts', 'jsx', 'tsx'],
    pattern: /(?:function|const)\s+\w+\s*(?:=|)\s*(?:\([^)]*\))?\s*(?:=>)?\s*\{[^}]*set\w+\s*\([^}]*return\s*(?:\(|<)/gms,
    message: '🔴 **State Update in Render**: Setting state during render causes infinite re-renders.',
    suggestion: 'Move state updates to event handlers or useEffect.'
  },

  // --- TYPESCRIPT ---
  {
    id: 'TS001',
    name: 'any Type',
    severity: 'info',
    languages: ['ts', 'tsx'],
    pattern: /:\s*any\b/g,
    message: 'ℹ️ **`any` Type**: Using `any` defeats the purpose of TypeScript.',
    suggestion: 'Use a specific type, `unknown` for truly unknown types, or generics.'
  },
  {
    id: 'TS002',
    name: 'Non-null Assertion',
    severity: 'warning',
    languages: ['ts', 'tsx'],
    pattern: /\w+!\./g,
    message: '⚠️ **Non-null Assertion**: `!.` bypasses null checking and can cause runtime errors.',
    suggestion: 'Use optional chaining (`?.`) or add a proper null check.'
  },

  // --- GENERAL ---
  {
    id: 'GEN001',
    name: 'Magic Number',
    severity: 'info',
    languages: ['*'],
    pattern: /(?:if|while|for|return|===?|!==?|[<>]=?)\s*\d{3,}/g,
    message: 'ℹ️ **Magic Number**: Large numeric literals should be named constants for readability.',
    suggestion: 'Extract to a named constant: `const MAX_RETRIES = 1000;`',
    contextFilter: (line) => !/(?:port|status|code|http|error|errno|0x|pixel|width|height|size)/i.test(line)
  },
  {
    id: 'GEN002',
    name: 'Long Function',
    severity: 'info',
    languages: ['*'],
    isBlockRule: true,
    check: (lines) => {
      const issues = [];
      let funcStart = -1;
      let braceDepth = 0;
      let funcName = '';
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const funcMatch = line.match(/(?:function|def|func|fn)\s+(\w+)/);
        if (funcMatch && funcStart === -1) {
          funcStart = i;
          funcName = funcMatch[1];
          braceDepth = 0;
        }
        if (funcStart !== -1) {
          braceDepth += (line.match(/{/g) || []).length;
          braceDepth -= (line.match(/}/g) || []).length;
          if (braceDepth <= 0 && i > funcStart) {
            const length = i - funcStart;
            if (length > 50) {
              issues.push({
                line: funcStart + 1,
                message: `ℹ️ **Long Function**: \`${funcName}\` is ${length} lines long. Consider breaking it up.`,
                suggestion: 'Functions over 50 lines are harder to test and maintain. Extract sub-functions.'
              });
            }
            funcStart = -1;
          }
        }
      }
      return issues;
    }
  }
];

// ============================================================================
// ANALYZER
// ============================================================================

function detectLanguage(filepath) {
  const ext = filepath.split('.').pop()?.toLowerCase();
  const map = {
    'js': 'js', 'mjs': 'js', 'cjs': 'js', 'jsx': 'jsx',
    'ts': 'ts', 'mts': 'ts', 'cts': 'ts', 'tsx': 'tsx',
    'py': 'py', 'pyw': 'py',
    'go': 'go',
    'rs': 'rust',
    'java': 'java',
    'rb': 'rb',
    'php': 'php',
    'c': 'c', 'h': 'c',
    'cpp': 'cpp', 'cc': 'cpp', 'cxx': 'cpp', 'hpp': 'cpp',
  };
  return map[ext] || ext;
}

function analyzeFile(filepath, content, minSeverity = 'warning') {
  const lang = detectLanguage(filepath);
  const lines = content.split('\n');
  const issues = [];
  const minSev = SEVERITY[minSeverity] || 0;

  for (const rule of rules) {
    // Skip if severity too low
    if (SEVERITY[rule.severity] < minSev) continue;

    // Skip if language doesn't match
    if (!rule.languages.includes('*') && !rule.languages.includes(lang)) continue;

    if (rule.isBlockRule) {
      // Block-level rules analyze the whole file
      const blockIssues = rule.check(lines);
      for (const issue of blockIssues) {
        issues.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          line: issue.line,
          message: issue.message,
          suggestion: issue.suggestion
        });
      }
    } else {
      // Line-level rules use regex
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Skip comments
        if (/^\s*(?:\/\/|#|\/\*|\*|--|;)/.test(line)) continue;

        // Reset regex lastIndex
        rule.pattern.lastIndex = 0;

        if (rule.pattern.test(line)) {
          // Apply context filter if present
          if (rule.contextFilter && !rule.contextFilter(line, filepath)) continue;

          issues.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            line: i + 1,
            message: rule.message,
            suggestion: rule.suggestion
          });
        }
      }
    }
  }

  return issues;
}

function analyzeDiff(files, minSeverity = 'warning') {
  const allIssues = [];

  for (const file of files) {
    if (!file.content || !file.filepath) continue;

    // Only analyze changed lines (if diff info available)
    const issues = analyzeFile(file.filepath, file.content, minSeverity);

    // If we have changed line numbers, filter to only those
    if (file.changedLines && file.changedLines.length > 0) {
      const changedSet = new Set(file.changedLines);
      const filtered = issues.filter(i => changedSet.has(i.line));
      allIssues.push({ filepath: file.filepath, issues: filtered });
    } else {
      allIssues.push({ filepath: file.filepath, issues });
    }
  }

  return allIssues;
}

function formatReviewComment(issue) {
  return `${issue.message}\n\n💡 **Suggestion**: ${issue.suggestion}\n\n<sub>Rule: ${issue.ruleId} | [Li Code Review](https://lbartoszcze.github.io/li-agent/) — Free AI code review</sub>`;
}

function generateSummary(allResults) {
  let totalIssues = 0;
  let errors = 0;
  let warnings = 0;
  let infos = 0;

  for (const result of allResults) {
    for (const issue of result.issues) {
      totalIssues++;
      if (issue.severity === 'error') errors++;
      else if (issue.severity === 'warning') warnings++;
      else infos++;
    }
  }

  if (totalIssues === 0) {
    return '✅ **Li Code Review**: No issues found. Code looks good! 🎉\n\n<sub>[Li Code Review](https://lbartoszcze.github.io/li-agent/) — Free AI-powered code review</sub>';
  }

  let summary = `## 🔍 Li Code Review Summary\n\nFound **${totalIssues}** issue${totalIssues === 1 ? '' : 's'}:\n`;
  if (errors > 0) summary += `- 🔴 **${errors}** error${errors === 1 ? '' : 's'}\n`;
  if (warnings > 0) summary += `- ⚠️ **${warnings}** warning${warnings === 1 ? '' : 's'}\n`;
  if (infos > 0) summary += `- ℹ️ **${infos}** info${infos === 1 ? '' : 's'}\n`;

  summary += `\n<sub>[Li Code Review](https://lbartoszcze.github.io/li-agent/) — Free AI-powered code review | Want deeper analysis? [Get a full audit](https://buy.stripe.com/cNi7sLex9bwm2qy8Iwd3i13)</sub>`;

  return summary;
}

module.exports = { analyzeFile, analyzeDiff, formatReviewComment, generateSummary, detectLanguage, rules };

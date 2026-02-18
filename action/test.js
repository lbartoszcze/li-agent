/**
 * Tests for Li Code Review analyzer
 */
const { analyzeFile, analyzeDiff, generateSummary, detectLanguage } = require('./src/analyzer');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  ✅ ${message}`);
  } else {
    failed++;
    console.log(`  ❌ ${message}`);
  }
}

function test(name, fn) {
  console.log(`\n${name}`);
  fn();
}

// --- Tests ---

test('Language Detection', () => {
  assert(detectLanguage('app.js') === 'js', 'Detects JavaScript');
  assert(detectLanguage('app.ts') === 'ts', 'Detects TypeScript');
  assert(detectLanguage('main.py') === 'py', 'Detects Python');
  assert(detectLanguage('main.go') === 'go', 'Detects Go');
  assert(detectLanguage('App.tsx') === 'tsx', 'Detects TSX');
});

test('SQL Injection Detection', () => {
  const code = 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)';
  const issues = analyzeFile('app.js', code, 'error');
  assert(issues.some(i => i.ruleId === 'SEC001'), 'Catches SQL injection');
});

test('eval() Detection', () => {
  const code = 'const result = eval(userInput);';
  const issues = analyzeFile('app.js', code, 'error');
  assert(issues.some(i => i.ruleId === 'SEC002'), 'Catches eval usage');
});

test('Hardcoded Secrets', () => {
  const code = 'const api_key = "sk-1234567890abcdef";';
  const issues = analyzeFile('config.js', code, 'error');
  assert(issues.some(i => i.ruleId === 'SEC003'), 'Catches hardcoded secrets');
});

test('XSS via innerHTML', () => {
  const code = 'element.innerHTML = userInput;';
  const issues = analyzeFile('app.js', code, 'error');
  assert(issues.some(i => i.ruleId === 'SEC005'), 'Catches innerHTML XSS');
});

test('Empty Catch Block', () => {
  const code = 'try { doSomething(); } catch (e) {}';
  const issues = analyzeFile('app.js', code, 'warning');
  assert(issues.some(i => i.ruleId === 'BUG004'), 'Catches empty catch');
});

test('Python Mutable Default', () => {
  const code = 'def process(items=[]):';
  const issues = analyzeFile('app.py', code, 'error');
  assert(issues.some(i => i.ruleId === 'PY001'), 'Catches mutable default');
});

test('Python Bare Except', () => {
  const code = 'except:';
  const issues = analyzeFile('app.py', code, 'warning');
  assert(issues.some(i => i.ruleId === 'PY002'), 'Catches bare except');
});

test('TypeScript any Type', () => {
  const code = 'function process(data: any) {';
  const issues = analyzeFile('app.ts', code, 'info');
  assert(issues.some(i => i.ruleId === 'TS001'), 'Catches any type');
});

test('No False Positives on Comments', () => {
  const code = '// eval() is dangerous, do not use it';
  const issues = analyzeFile('app.js', code, 'info');
  assert(!issues.some(i => i.ruleId === 'SEC002'), 'Skips eval in comments');
});

test('Clean Code Detection', () => {
  const code = 'const x = 1 + 2;\nconsole.log(x);';
  const issues = analyzeFile('app.js', code, 'error');
  assert(issues.length === 0, 'Clean code has no errors');
});

test('Summary Generation', () => {
  const results = [
    { filepath: 'app.js', issues: [{ severity: 'error' }, { severity: 'warning' }] },
    { filepath: 'lib.js', issues: [{ severity: 'info' }] }
  ];
  const summary = generateSummary(results);
  assert(summary.includes('3'), 'Summary includes total count');
  assert(summary.includes('error'), 'Summary mentions errors');
  assert(summary.includes('Li Code Review'), 'Summary has branding');
});

test('Empty Summary', () => {
  const results = [{ filepath: 'app.js', issues: [] }];
  const summary = generateSummary(results);
  assert(summary.includes('No issues found'), 'Clean summary for no issues');
});

test('SSL Verification Disabled', () => {
  const code = 'requests.get(url, verify=False)';
  const issues = analyzeFile('app.py', code, 'error');
  assert(issues.some(i => i.ruleId === 'SEC008'), 'Catches disabled SSL verification');
});

// --- Results ---
console.log(`\n${'═'.repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
} else {
  console.log('All tests passed! ✅');
}

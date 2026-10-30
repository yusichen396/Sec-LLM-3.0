const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const ts = require('typescript');

function client(fetch) {
  const source = readFileSync(path.join(__dirname, '../lib/agent-api.ts'), 'utf8');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  });
  const context = { exports: {}, process: { env: {} }, fetch, TextDecoder, AbortController };
  vm.runInNewContext(outputText, context);
  return context.exports;
}

test('premature EOF invokes recovery instead of silently leaving the task running', async () => {
  const api = client(async () => new Response('data: {"type":"log","message":"started"}\n\n'));
  const logs = [];
  const error = await new Promise((resolve) => {
    api.createAgentStream('session', (line) => logs.push(line), () => assert.fail('not completed'), resolve);
  });
  assert.deepEqual(logs, ['started']);
  assert.match(error, /before task completion/);
});

test('completion event terminates cleanly without reporting an EOF error', async () => {
  const errors = [];
  const api = client(async () => new Response('data: {"type":"done","status":"failed","findings_count":2}\n\n'));
  let controller;
  const completed = await new Promise((resolve) => {
    controller = api.createAgentStream('session', () => {}, (status, count) => resolve({ status, count }),
      (error) => errors.push(error));
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(completed, { status: 'failed', count: 2 });
  assert.equal(controller.signal.aborted, true);
  assert.deepEqual(errors, []);
});

test('HTTP failure reaches recovery', async () => {
  const api = client(async () => new Response('', { status: 503 }));
  const error = await new Promise((resolve) => {
    api.createAgentStream('session', () => {}, () => assert.fail('not completed'), resolve);
  });
  assert.match(error, /503/);
});

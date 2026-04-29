import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /api/agent/chat', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'prompt_injection',
        'csrf',
        'xss',
        'sqli',
        'server_side_js_injection',
        'osi'
      ],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'carlcj/DVAIA-Damn-Vulnerable-AI-Application:master',
        databases: ['Qdrant'],
        user_roles: null
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/agent/chat`,
      body: {
        prompt: 'test prompt',
        model_id: 'test_model',
        messages: [
          {
            role: 'user',
            content: 'test message'
          }
        ],
        tool_names: ['tool1', 'tool2'],
        max_steps: 10,
        timeout: 300
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
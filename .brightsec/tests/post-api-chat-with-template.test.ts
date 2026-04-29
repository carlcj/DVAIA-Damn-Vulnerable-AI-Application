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

test('POST /api/chat-with-template', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['ssti', 'prompt_injection', 'xss', 'csrf', 'sqli'],
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
      url: `${baseUrl}/api/chat-with-template`,
      body: {
        template: '<script>alert(1)</script>',
        user_input: 'test',
        model_id: '1'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
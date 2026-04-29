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

test('POST /api/chat', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'prompt_injection',
        'xss',
        'ssrf',
        'sqli',
        'csrf',
        'bopla'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
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
      url: `${baseUrl}/api/chat`,
      body: {
        prompt: 'test prompt',
        messages: [{ role: 'user', content: 'test message' }],
        model_id: 'test-model',
        options: { max_tokens: 100, num_predict: 1 },
        context_from: 'test-context',
        document_id: 'test-doc-id',
        url: 'https://example.com',
        rag_query: 'test-query'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
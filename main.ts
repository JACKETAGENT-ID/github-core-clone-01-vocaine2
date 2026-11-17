// forge2 entrypoint — lifecycle only; all behaviour lives in app.ts.
// Adapted from the kit starter: listen on an ephemeral port, register once with
// the environment, long-poll GET /done, exit 0 when the run finishes.

import { createApp } from './app.ts';

const envUrl = process.env.MAKEFUN_ENV_URL;
if (!envUrl) {
  console.error('MAKEFUN_ENV_URL is not set');
  process.exit(1);
}

const app = createApp();

async function register(port: number): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      const res = await fetch(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
      });
      if (res.status === 400 || res.status === 405) {
        console.error(`register rejected with ${res.status}; exiting`);
        process.exit(1);
      }
      if (res.ok) return;
      console.error(`register attempt ${attempt + 1} failed: ${res.status}`);
    } catch (err) {
      console.error(`register attempt ${attempt + 1} error: ${(err as Error).message}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 500 * (attempt + 1)));
  }
  console.error('register failed after 20 attempts; exiting');
  process.exit(1);
}

async function waitDone(): Promise<void> {
  for (;;) {
    try {
      const res = await fetch(`${envUrl}/done`);
      if (res.ok) {
        const body = (await res.json()) as { done?: boolean };
        if (body.done) return;
      }
    } catch {
      // environment not reachable yet; keep polling
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

const server = app.listen(0, '127.0.0.1', async () => {
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  console.log(`forge2 listening on 127.0.0.1:${port}`);
  await register(port);
  await waitDone();
  server.close(() => process.exit(0));
});

/**
 * Welcome to Cloudflare Workers!
 *
 * This is a template for a Scheduled Worker: a Worker that can run on a
 * configurable interval:
 * https://developers.cloudflare.com/workers/platform/triggers/cron-triggers/
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Run `curl "http://localhost:8787/__scheduled?cron=*+*+*+*+*"` to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.toml`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

interface ApiResponse {
  message: string;
  result: Array<{ "?column?": number }>;
}

export default {
	fetch(req, env, ctx) {
		return new Response('https://qmp.ezegatica.com', { status: 200 });
	},
	// The scheduled handler is invoked at the interval set in our wrangler.toml's
	// [[triggers]] configuration.
	async scheduled(event, env, ctx): Promise<void> {
		// A Cron Trigger can make requests to other endpoints on the Internet,
		// publish to a Queue, query a D1 Database, and much more.
		const prod = await fetch('https://qmp.ezegatica.com/api/health/db');
		const body = await prod.json() as ApiResponse;	
		// You could store this result in KV, write to a D1 Database, or publish to a Queue.
		// In this template, we'll just log the result:
		console.log(`${new Date().toLocaleString('es-AR')} > trigger fired at ${event.cron}: ${body.message}`);
	},
} satisfies ExportedHandler<Env>;

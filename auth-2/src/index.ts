import { WorkerEntrypoint } from 'cloudflare:workers';

/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.toml`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export default {
	async fetch(request, env, ctx): Promise<Response> {
		return new Response('Hello World!');
	},
} satisfies ExportedHandler<Env>;

export class AdminEntrypoint extends WorkerEntrypoint {
	async echo(message: string) {
		await Promise.resolve();
		return `Hello, ${message}`;
	}

	async sum(a: number, b: number) {
		await Promise.resolve();
		return a + b;
	}
}

import { WorkerEntrypoint } from 'cloudflare:workers';
import jwt from '@tsndr/cloudflare-worker-jwt';

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

export default class AuthWorker extends WorkerEntrypoint<Env> {
	// Currently, entrypoints without a named handler are not supported
	async fetch() {
		return new Response(null, { status: 404 });
	}

	async validate(token: string) {
		try {
			const secretNullable = (await this.env.USERS_KV.get('secret')) as string;
			const valid = await jwt.verify(token, secretNullable, { algorithm: 'HS256' });
			return valid;
		} catch (error) {
			return false;
		}
	}
}

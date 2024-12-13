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

import { WrongProtocolException } from './exceptions';
import { ApiHandler } from './handlers/api';
import { OptionsHandler } from './handlers/options';
import { RootHandler } from './handlers/root';
import { UrlHandler } from './handlers/url';

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const { pathname, protocol } = new URL(request.url);
		// jijiji
		if ('https:' !== protocol || 'https' !== request.headers.get('x-forwarded-proto')) {
			return new WrongProtocolException();
		}

		// el fucking CORS
		if (request.method === 'OPTIONS') {
			return new OptionsHandler(request, env, ctx).fetch();
		}

		// no leeches
		if (pathname === '/') {
			return new RootHandler(request, env, ctx).fetch();
		}

		// si arranca con /api se va a la api (quien hubiese dicho)
		if (pathname.startsWith('/api')) {
			return new ApiHandler(request, env, ctx).fetch();
		}

		// todo el resto se maneja como si fuese una url
		return new UrlHandler(request, env, ctx).fetch();
	},
} satisfies ExportedHandler<Env>;

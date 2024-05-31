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
	async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const { pathname } = new URL(req.url);

		switch (pathname) {
			case '/status':
				const randomNumber = Math.floor(Math.random() * 10) + 1;
				if (randomNumber === 1) {
					return new Response('SCHEDULED MAINTENANCE', { status: 200 });
				} else if (randomNumber === 2) {
					return new Response('HIGH LATENCY', { status: 200 });
				} else if (randomNumber === 3) {
					return new Response('SERVICE DOWN, CHECK AGAIN LATER', { status: 200 });
				} else {
					return new Response('OK', { status: 200 });
				}
			case '/balance': {
				const randomNumber = Math.floor(Math.random() * 1000);
				return new Response(randomNumber.toString(), { status: 200 });
			}
			case '/transaction': {
				const randomNumber = Math.floor(Math.random() * 4) + 1;
				if (randomNumber === 1) {
					return new Response('Insuficient balance', { status: 400 });
				}

				return new Response('Transaction successful', { status: 200 });
			}

			default: {
				return new Response('Hello World!');
			}
		}
	},
};

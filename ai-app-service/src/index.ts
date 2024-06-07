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
		const { pathname, searchParams } = new URL(req.url);

		switch (pathname) {
			case '/status':
				const randomNumber = Math.floor(Math.random() * 4) + 1;
				let message: string;

				if (randomNumber === 1) {
					message = 'SCHEDULED MAINTENANCE';
				} else if (randomNumber === 2) {
					message = 'HIGH LATENCY';
				} else if (randomNumber === 3) {
					message = 'SERVICE DOWN, CHECK AGAIN LATER';
				} else {
					message = 'OK';
				}

				console.log(`> System Status: ${message}`);
				return new Response(message, { status: 200 });
			case '/balance': {
				const randomNumber = Math.floor(Math.random() * 1000);

				console.log(`> Account Balance: $${randomNumber}`);
				return new Response(randomNumber.toString(), { status: 200 });
			}
			case '/transaction': {
				let randomNumber = Math.floor(Math.random() * 2) + 1;
				let message: string;
				let status: number;

				const receiptent = searchParams.get('recipient');
				if (receiptent === 'Matt') {
					randomNumber = 1; // Si el chabon se llama Matt, falla 100% (para demo)
				} else if (receiptent === 'John') {
					randomNumber = 2; // Si el chabon se llama John, pasa 100% (para demo)
				}

				if (randomNumber === 1) {
					message = 'Insufficient balance';
					status = 400;
				} else {
					message = 'Transaction successful';
					status = 200;
				}

				console.log(`> Transaction Status: ${message}`);

				return new Response(message, { status: status });
			}

			case '/account-status': {
				const randomNumber = Math.floor(Math.random() * 5) + 1;
				let message: string;

				if (randomNumber === 1) {
					message = 'SUSPICIOUS ACTIVITY';
				} else if (randomNumber === 2) {
					message = 'INACTIVITY LOCK';
				} else if (randomNumber === 3) {
					message = 'PASSWORD EXPIRED';
				} else if (randomNumber === 4) {
					message = 'SECURITY LOCK';
				} else {
					message = 'ACCOUNT OK';
				}

				console.log(`> Account Status: ${message}`);

				return new Response(message, { status: 200 });
			}

			default: {
				return new Response('Hello World!');
			}
		}
	},
};

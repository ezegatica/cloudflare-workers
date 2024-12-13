import { UnauthorizedException } from '../exceptions';
import { BaseHandler } from './base';
import { Router } from '@tsndr/cloudflare-worker-router';
import { WorkerEntrypoint } from "cloudflare:workers";

const router = new Router<Env>();

router.use(({ env, req }) => {
	// return new UnauthorizedException();
});

router.get('/url', async ({ req, env }) => {
    const a = await env.AUTH.echo("pepepepepepe");
	const list = await env.URLS_BINDING.list();
	return Response.json(list.keys, { status: 200 });
});

export class ApiHandler extends BaseHandler {
	async fetch(): Promise<Response> {
		// this.request.url is the full URL of the request
		// const {pathname} = new URL(this.request.url); is the same as, in this context, /api/:whatever
		// i want to return the full URL of the request but without the /api prefix
		// so if im in server.com/api/whatever i want to return server.com/whatever

		return router.handle(new Request(this.request.url.replace('/api', ''), this.request), this.env);
	}
}

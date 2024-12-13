import { InternalServerErrorException, MissingFieldsException, UnauthorizedException } from '../exceptions';
import { BaseHandler } from './base';
import { Router } from '@tsndr/cloudflare-worker-router';
import { Metadata, RequestBody } from '../types';

const router = new Router<Env>();

router.use(async ({ env, req }) => {
	try {
		const header = req.headers.get('Authorization');
		const token = header?.split(' ')[1];
		if (!token) {
			throw new UnauthorizedException();
		}
		const isValidToken = await env.AUTH.validate(token);
		if (!isValidToken) {
			throw new UnauthorizedException();
		}
	} catch (error) {
		console.error(error);
		if (error instanceof Response) {
			return error;
		}
		return new InternalServerErrorException();
	}
});

router.get('/url', async ({ req, env }) => {
	const list = await env.URLS_BINDING.list();
	return Response.json(list.keys, { status: 200 });
});

router.post('/url', async ({ req, env }) => {
	const body = await req.json<RequestBody>();

	if (!body || !body.url || !body.slug) {
		return new MissingFieldsException();
	}

	const { url, slug } = body;

	const existing = await env.URLS_BINDING.get(slug);
	if (existing) {
		return new Response('URL con ese slug ya existe', { status: 400 });
	}

	const validUrl = URL.canParse(url);
	if (!validUrl) {
		return new Response('Invalid URL', { status: 400 });
	}

	if (slug === 'api') {
		return new Response('El slug contiene una palabra reservada', { status: 400 });
	}

	await env.URLS_BINDING.put(slug, url, {
		metadata: {
			created: new Date().toISOString(),
			count: 0,
		} satisfies Metadata,
	});
	return Response.json({ status: 201 });
});

router.delete('/url/:slug', async ({ req, env }) => {
	const { slug } = req.params;
	const existing = await env.URLS_BINDING.get(slug);
	if (!existing) {
		return new Response('URL no existe', { status: 404 });
	}

	await env.URLS_BINDING.delete(slug);
	return Response.json({ status: 200 });
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

import { NotFoundException } from '../exceptions';
import { Metadata } from '../types';
import { BaseHandler } from './base';

export class UrlHandler extends BaseHandler {
	async fetch(): Promise<Response> {
		const { pathname } = new URL(this.request.url);
		let slug = pathname.slice(1);
        const isJson = slug.endsWith('.json');
        
        if (isJson) {
            slug = slug.slice(0, -5);
        }

		const url = await this.env.URLS_BINDING.get(slug);

		if (!url) {
			return new NotFoundException();
		}

		if (isJson) {
			return Response.json({ url }, { status: 200 });
		}

		// Lo hace asincrono para no bloquear la query
		this.ctx.waitUntil(this.updateMetadata(slug, url));

		return Response.redirect(url, 302);
	}

	async updateMetadata(slug: string, url: string): Promise<void> {
		const urlWithMetadata = await this.env.URLS_BINDING.getWithMetadata<Metadata>(slug);
		const count = (urlWithMetadata?.metadata?.count || 0) + 1;
		const created = urlWithMetadata?.metadata?.created || new Date(0).toISOString();
		await this.env.URLS_BINDING.put(slug, url, { metadata: { count, created } });
	}
}

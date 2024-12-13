import { NotFoundException } from '../exceptions';
import { BaseHandler } from './base';

type Metadata = {
    count: number;
};

export class UrlHandler extends BaseHandler {
    async fetch(): Promise<Response> {
        const { pathname } = new URL(this.request.url);
        const slug = pathname.slice(1);
        const url = await this.env.URLS_BINDING.get(slug, {cacheTtl: 60 * 60 * 24});
        
        if (!url) {
            return new NotFoundException();
        }
        
        // Lo hace asincrono para no bloquear la query
        this.ctx.waitUntil(this.updateCount(slug, url));
        
        return Response.redirect(url, 302);
    }
    
    async updateCount(slug: string, url: string): Promise<void> {
        const urlWithMetadata = await this.env.URLS_BINDING.getWithMetadata<Metadata>(slug);
        const count = (urlWithMetadata?.metadata?.count || 0) + 1;
        await this.env.URLS_BINDING.put(slug, url, {metadata: {count}});
    }
}

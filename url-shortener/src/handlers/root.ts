import { BaseHandler } from './base';

export class RootHandler extends BaseHandler {
    async fetch(): Promise<Response> {
        return Response.redirect("https://ezegatica.com", 301)
    }
}

import { BaseHandler } from './base';

export class ApiHandler extends BaseHandler {
    async fetch(): Promise<Response> {
        return Response.json({ message: 'Hello from the API' });
    }
}

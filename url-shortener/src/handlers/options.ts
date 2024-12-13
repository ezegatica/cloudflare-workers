import { BaseHandler } from './base';

export class OptionsHandler extends BaseHandler {
    async fetch(): Promise<Response> {
        if (
            this.request.headers.get("Origin") !== null &&
            this.request.headers.get("Access-Control-Request-Method") !== null &&
            this.request.headers.get("Access-Control-Request-Headers") !== null
          ) {
            // Handle CORS preflight requests.
            return new Response(null, {
              headers: {
                  "Access-Control-Allow-Origin": "*",
                  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
                  "Access-Control-Max-Age": "86400",
                  "Access-Control-Allow-Headers": this.request.headers.get(
                      "Access-Control-Request-Headers"
                    ) as string,
              },
            });
          } else {
            // Handle standard OPTIONS request.
            return new Response(null, {
              headers: {
                Allow: "GET, HEAD, POST, OPTIONS",
              },
            });
          }
    }
}

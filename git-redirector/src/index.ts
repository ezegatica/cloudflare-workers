/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `wrangler dev src/index.ts` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `wrangler publish src/index.ts --name my-worker` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export interface Env {
  // Example binding to KV. Learn more at https://developers.cloudflare.com/workers/runtime-apis/kv/
  // MY_KV_NAMESPACE: KVNamespace;
  //
  // Example binding to Durable Object. Learn more at https://developers.cloudflare.com/workers/runtime-apis/durable-objects/
  // MY_DURABLE_OBJECT: DurableObjectNamespace;
  //
  // Example binding to R2. Learn more at https://developers.cloudflare.com/workers/runtime-apis/r2/
  // MY_BUCKET: R2Bucket;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const base = "https://github.com/ezegatica/";
    const statusCode = 301;
    const url = new URL(request.url);
    const { pathname, searchParams } = url;
    const path = pathname.split("/");
    const branch = searchParams.get('branch') || 'main';

    const firstPath = path[1];
    const restPath = path.slice(2).join("/");

    if (restPath) {
      const destinationURL = base + firstPath + `/blob/${branch}/` + restPath;
      return Response.redirect(destinationURL, statusCode);
    } else {
      const destinationURL = base + firstPath;
      return Response.redirect(destinationURL, statusCode);
    }
  },
};

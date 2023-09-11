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
	//
	// Example binding to a Service. Learn more at https://developers.cloudflare.com/workers/runtime-apis/service-bindings/
	// MY_SERVICE: Fetcher;
	
	TWITTER_CONSUMER_KEY: string;
	TWITTER_CONSUMER_SECRET: string;
}

export default {
	async fetch(
		request: Request,
		env: Env,
		_ctx: ExecutionContext
	): Promise<Response> {
		return Response.json({error: "Twitter Api 2.0 destroyed this app. Thanks for everything :("}, {status: 555});
		const url = new URL(request.url);
		const path = url.pathname.split("/");
		const tweetId = path[3];

		if (!tweetId){
			return Response.json({error: "No tweet id found"}, {status: 400});
		}

		const params = { id: tweetId, tweet_mode: 'extended' };

		const {access_token: token} = await fetch('https://api.twitter.com/oauth2/token?grant_type=client_credentials', {
			method: 'POST',
			headers: {
				'Authorization': `Basic ${btoa(`${env.TWITTER_CONSUMER_KEY}:${env.TWITTER_CONSUMER_SECRET}`)}`,
				'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
			},
		}).then((res) => res.json()) as {access_token: string};

		const tweet = await fetch(`https://api.twitter.com/1.1/statuses/show.json?${new URLSearchParams(params)}`, {
			headers:  {
				'Authorization': `Bearer ${token}`,
				'Content-Type': 'application/json',
			},
		}).then((res) => res.json()) as any;
		var bitrate = 0;
        var hq_video_url;

		try {
			for (var j = 0; j < tweet.extended_entities.media[0].video_info.variants.length; j++) {
				if (tweet.extended_entities.media[0].video_info.variants[j].bitrate) {
					if (tweet.extended_entities.media[0].video_info.variants[j].bitrate > bitrate) {
						bitrate = tweet.extended_entities.media[0].video_info.variants[j].bitrate;
						hq_video_url = tweet.extended_entities.media[0].video_info.variants[j].url;
					}
				}
			}
		} catch (error) {
			return Response.json({error: "Tweet is not a video"}, {status: 400});
		}
		

		return Response.redirect(hq_video_url, 302);
	},
};

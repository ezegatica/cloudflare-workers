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

import { fetchTweet } from "./react-tweet";

export default {
	async fetch(request, env, ctx): Promise<Response> {
		// return new Response('Hello World!');
		const url = new URL(request.url);
		const path = url.pathname.split("/");
		const tweetId = path[3];

		if (!tweetId) {
			return Response.json({ error: "No tweet id found" }, { status: 400 });
		}

		const promise = fetchTweet(tweetId, {
			headers: {
				"User-Agent": "PostmanRuntime/7.37.3",
				Accept: "*/*",
				"Accept-Encoding": "gzip, deflate, br",
				Connection: "keep-alive",
				"cache-control": "no-cache"
			},
		});

		ctx.waitUntil(promise);

		const tweet = await promise;

		let bitrate = 0;
		let hq_video_url = null;
		/* 

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
		*/
		if ('data' in tweet && tweet.data.mediaDetails && tweet.data.mediaDetails[0] && tweet.data.mediaDetails[0].type === "video") {
			try {
				for (let j = 0; j < tweet.data.mediaDetails[0].video_info.variants.length; j++) {
					const video = tweet.data.mediaDetails[0].video_info.variants[j];
					if (video.bitrate) {
						if (video.bitrate > bitrate) {
							bitrate = video.bitrate;
							hq_video_url = video.url;
						}
					}
				}

				if (hq_video_url === null) {
					return Response.json({ error: "No video found" }, { status: 400 });
				}

				// return new Response(hq_video_url);
				return Response.redirect(hq_video_url, 307);

			} catch (error) {
				return Response.json({ error: "Tweet is not a video" }, { status: 400 });
			}
		} else {
			return Response.json({ tweetId, error: "Tweet not found" }, { status: 404 });
		}
	},
} satisfies ExportedHandler<Env>;

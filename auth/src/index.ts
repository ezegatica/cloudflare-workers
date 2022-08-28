/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `wrangler dev src/index.ts` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `wrangler publish src/index.ts --name my-worker` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import {
  EmptyBodyException,
  LoginFailedException,
  NotFoundException,
  WrongMethodException,
  WrongProtocolException,
} from "./exceptions";
import { IUser } from "./interfaces";
import jwt from "@tsndr/cloudflare-worker-jwt";

export interface Env {
  // Example binding to KV. Learn more at https://developers.cloudflare.com/workers/runtime-apis/kv/
  USERS: KVNamespace;

  token: string;
  //
  // Example binding to Durable Object. Learn more at https://developers.cloudflare.com/workers/runtime-apis/durable-objects/
  // MY_DURABLE_OBJECT: DurableObjectNamespace;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext
  ): Promise<Response> {
    const { protocol, pathname } = new URL(request.url);

    if (
      "https:" !== protocol ||
      "https" !== request.headers.get("x-forwarded-proto")
    ) {
      return new WrongProtocolException();
    }

    switch (pathname) {
      case "/":
        return Response.redirect("https://ezegatica.com");
      case "/login":
        if (request.method !== "POST") {
          return new WrongMethodException();
        }
        if (request.headers.get("Content-Type") !== "application/json") {
          return new EmptyBodyException();
        }
        const body = (await request.json()) as IUser;
        const password = await env.USERS.get(`user:${body.email}`);
        if (!password || password !== body.password) {
          return new LoginFailedException();
        }
        const secretNullable = await env.USERS.get("secret");

        const secret = JSON.parse(JSON.stringify(secretNullable)) as string;

        const token = await jwt.sign({ email: body.email }, secret, {
          algorithm: "HS256",
        });

        return new Response(token);
      case "check": {
        const token = await jwt.verify(
          request.headers.get("Authorization") as string,
          env.token,
          { algorithm: "HS256" }
        );
        return new Response(token);
      }

      default: {
        return new NotFoundException();
      }
    }
  },
};

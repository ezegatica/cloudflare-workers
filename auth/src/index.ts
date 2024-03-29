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
  UnauthorizedException,
  WrongMethodException,
  WrongProtocolException,
} from "./exceptions";
import { IUser } from "./interfaces";
import jwt from "@tsndr/cloudflare-worker-jwt";

export interface Env {
  // Example binding to KV. Learn more at https://developers.cloudflare.com/workers/runtime-apis/kv/
  USERS: KVNamespace;

  //
  // Example binding to Durable Object. Learn more at https://developers.cloudflare.com/workers/runtime-apis/durable-objects/
  // MY_DURABLE_OBJECT: DurableObjectNamespace;
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

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

    if (request.method === "OPTIONS") {
      return this.handleOptions(request);
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
        return new Response(token, {
            headers: {
              "Content-Type": "text/plain",
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, OPTIONS",
              "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept",
              "Set-Cookie": `token=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=31536000;`,
            }
        });

      case "/check": {
        if (request.method !== "POST") {
          return new WrongMethodException();
        }
        const token = request.headers.get("Authorization")?.split(" ")[1] as string;
        const valid = await this.verifyToken(env, token);
       return Response.json({
          valid
        }, {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept",
          }
        });
      }

      default: {
        return new NotFoundException();
      }
    }
  },
  async handleOptions(request: Request): Promise<Response> {
    if (
      request.headers.get("Origin") !== null &&
      request.headers.get("Access-Control-Request-Method") !== null &&
      request.headers.get("Access-Control-Request-Headers") !== null
    ) {
      // Handle CORS preflight requests.
      return new Response(null, {
        headers: {
          ...corsHeaders,
          "Access-Control-Allow-Headers": request.headers.get(
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
  },
  async verifyToken(env: Env, token: string): Promise<boolean> {
    const secretNullable = await env.USERS.get("secret");

    const secret = JSON.parse(JSON.stringify(secretNullable)) as string;

    try {
      const valid = await jwt.verify(token, secret, { algorithm: "HS256" });
      return valid;
    } catch (error) {
      return false;
    }
  },
};

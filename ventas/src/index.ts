import * as Realm from "realm-web";
import { IItem } from "./interfaces";
import * as utils from "./utils";
import jwt from "@tsndr/cloudflare-worker-jwt";
import {
  MongoAuthenticationException,
  UnauthorizedException,
  WrongProtocolException,
} from "./exceptions";

// Define type alias; available via `realm-web`
type Document = globalThis.Realm.Services.MongoDB.Document;

// Declare the interface for a "todos" document
interface Item extends Document {
  nombre: string;
  short_descripcion: string;
  descripcion: string;
  imagen: string[];
  precio: number;
  vendido: boolean;
}

let App: Realm.App;
const ObjectId = Realm.BSON.ObjectID;

export interface Env {
  // Example binding to KV. Learn more at https://developers.cloudflare.com/workers/runtime-apis/kv/
  USERS: KVNamespace;
  //
  // Example binding to Durable Object. Learn more at https://developers.cloudflare.com/workers/runtime-apis/durable-objects/
  // MY_DURABLE_OBJECT: DurableObjectNamespace;
  //
  // Example binding to R2. Learn more at https://developers.cloudflare.com/workers/runtime-apis/r2/
  // MY_BUCKET: R2Bucket;
  REALM_APPID: string;

  API_KEY: string;

  ENV: string;
}

export default {
  async fetch(
    req: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const { protocol, pathname } = new URL(req.url);
    if (pathname === "/") {
      return Response.redirect("https://ezegatica.com");
    }

    App = App || new Realm.App(env.REALM_APPID);
    if (
      "https:" !== protocol ||
      "https" !== req.headers.get("x-forwarded-proto")
    ) {
      return new WrongProtocolException();
    }
    const token = req.headers.get("Authorization")?.split(" ")[1] as string;
    const valid = await this.verifyToken(env, token);
    if (!valid) {
      return new UnauthorizedException();
    }

    try {
      const credentials = Realm.Credentials.apiKey(env.API_KEY);
      // Attempt to authenticate
      var user = await App.logIn(credentials);
      var client = user.mongoClient("mongodb-atlas");
    } catch (err) {
      return new MongoAuthenticationException();
    }

    // Grab a reference to the "cloudflare.todos" collection
    const collection = client.db(env.ENV).collection<Item>("items");

    return new Response("ENV: " + env.ENV);
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

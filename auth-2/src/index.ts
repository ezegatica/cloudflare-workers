import { WorkerEntrypoint } from 'cloudflare:workers';
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import qs from 'qs';
import { loginPage, registerPage } from './templates';
import appsList from './apps.json';
import { AppListItem } from './interfaces';
import jwt from '@tsndr/cloudflare-worker-jwt';

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

export default class AuthWorker extends WorkerEntrypoint<Env> {
  private appsList: Record<string, AppListItem> = appsList;

  async fetch(request: Request) {
    const url = new URL(request.url);
    if (url.pathname === '/') return new Response('Hello World!');
    if (url.pathname === '/login' && request.method === 'GET') {
      return this.renderLoginPage(url, this.env);
    }
    if (url.pathname === '/login' && request.method === 'POST') {
      return this.handleLogin(request, this.env);
    }
    if (url.pathname === '/auth/google' && request.method === 'GET') {
      return this.handleGoogleAuth(url, this.env);
    }
    if (url.pathname === '/auth/google/callback' && request.method === 'GET') {
      return this.handleGoogleCallback(url, this.env);
    }
    if (url.pathname === '/revoke' && request.method === 'POST') {
      return this.handleRevoke(request, this.env);
    }
    if (url.pathname === '/register' && request.method === 'GET') {
      return this.renderRegisterPage(url, this.env);
    }
    if (url.pathname === '/register' && request.method === 'POST') {
      return this.handleRegister(request, this.env);
    }
    if (url.pathname === '/public-key' && request.method === 'GET') {
      return this.handlePublicKey();
    }
    if (url.pathname === '/validate' && request.method === 'POST') {
      const { token } = await request.json() as { token: string };
      const valid = await this.validateSSO(token, this.env);
      console.log({valid})
      return new Response(JSON.stringify({ valid }), { headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('Not Found', { status: 404 });
  }

  private async getKeys(env: Env) {
    const privPem = env.PRIVATE_KEY_SECRET; // private key from secret binding
    const pubPem = env.PUBLIC_KEY;
    const privateKey = await importPKCS8(privPem, 'RS256');
    const publicKey = await importSPKI(pubPem, 'RS256');
    return { privateKey, publicKey };
  }

  private async renderLoginPage(url: URL, env: Env) {
    const appName = url.searchParams.get('app')!;
    if (!appName) return new Response('Insert an app', { status: 400 });
    const app = this.appsList[appName];
    if (!app) return new Response('Invalid app', { status: 400 });
    return new Response(loginPage(app), { headers: { 'Content-Type': 'text/html' } });
  }

  private async handleLogin(request: Request, env: Env) {
    const { email, password, app } = Object.fromEntries(await request.formData() as any);
    const appObj = this.appsList[app];
    if (!appObj) return new Response('Invalid app', { status: 400 });
    const db = env.USERS_DB;
    const userRes = await db.prepare('SELECT id, email, password, role FROM users WHERE email = ?').bind(email).first<{id:string,email:string,password:string,role:string}>();
    if (!userRes) return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    const match = await bcrypt.compare(password, userRes.password);
    if (!match) return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    const { privateKey } = await this.getKeys(env);
    const accessJti = uuidv4();
    const accessToken = await new SignJWT({ sub: userRes.id, role: userRes.role, jti: accessJti })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setExpirationTime('90d')
      .sign(privateKey);
    // store access jti
    await db.prepare('INSERT INTO tokens (jti, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(accessJti, userRes.id, Math.floor(Date.now()/1000) + 90*24*3600).run();
    const redirectUrl = new URL(appObj.redirect_url);
    redirectUrl.searchParams.set('access_token', accessToken);
    return new Response(JSON.stringify({ redirect: redirectUrl.toString() }), { headers: { 'Content-Type': 'application/json' } });
  }

  private async handleRevoke(request: Request, env: Env) {
    const { access_token } = await request.json() as { access_token: string };
    const { publicKey } = await this.getKeys(env);
    let payload;
    try {
      const { payload: pl } = await jwtVerify(access_token, publicKey, { algorithms: ['RS256'] });
      payload = pl as any;
    } catch {
      return new Response('Invalid token', { status: 400 });
    }
    const db = env.USERS_DB;
    const res = await db.prepare('UPDATE tokens SET revoked = 1 WHERE jti = ?').bind(payload.jti).run();
    if (res.success) return new Response('Token revoked', { status: 200 });
    return new Response('Failed to revoke', { status: 500 });
  }

  private async handleGoogleAuth(url: URL, env: Env) {
    const appName = url.searchParams.get('app');
    if (!appName) return new Response('Invalid app', { status: 400 });
    const app = this.appsList[appName];
    if (!app) return new Response('Invalid app', { status: 400 });
    const state = uuidv4();
    await env.USERS_KV.put(`oauth_state_${state}`, appName as string, { expirationTtl: 300 });
    const params = qs.stringify({
      response_type: 'code', client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: env.GOOGLE_REDIRECT_URI, scope: 'openid email profile', state
    });
    return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, 302);
  }

  private async handleGoogleCallback(url: URL, env: Env) {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (!code || !state) return new Response('Missing code/state', { status: 400 });
    const appName = await env.USERS_KV.get(`oauth_state_${state}`);
    if (!appName) return new Response('Invalid state', { status: 400 });
    await env.USERS_KV.delete(`oauth_state_${state}`);
    // exchange code
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'},
      body: qs.stringify({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: env.GOOGLE_REDIRECT_URI, grant_type: 'authorization_code' })
    });
    const tokenJson = await tokenRes.json() as { access_token: string; id_token?: string };
    const userinfoRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: `Bearer ${tokenJson.access_token}` } });
    const { sub: googleId, email } = await userinfoRes.json() as any;
    const db = env.USERS_DB;
    let user = await db.prepare('SELECT id, role, password FROM users WHERE google_id = ?').bind(googleId).first<{id:string,role:string,password?:string}>();
    if (user && user.password) return new Response('Account uses password login', { status: 400 });
    if (!user) {
      const id = uuidv4();
      await db.prepare('INSERT INTO users (id, email, google_id, role) VALUES (?, ?, ?, ?)')
        .bind(id, email, googleId, 'user').run();
      user = { id, role: 'user' } as any;
    }
    // create tokens
    const { privateKey } = await this.getKeys(env);
    const accessJti = uuidv4();
    const accessToken = await new SignJWT({ sub: user!.id, role: user!.role, jti: accessJti })
      .setProtectedHeader({ alg: 'RS256' }).setIssuedAt().setExpirationTime('90d').sign(privateKey);
    await db.prepare('INSERT INTO tokens (jti, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(accessJti, user!.id, Math.floor(Date.now()/1000) + 90*24*3600).run();
    // redirect back to app
    const app = this.appsList[appName];
    if (!app) return new Response('Invalid app', { status: 400 });
    const redirectUrl = new URL(app.redirect_url);
    redirectUrl.searchParams.set('access_token', accessToken);
    return Response.redirect(redirectUrl.toString(), 302);
  }

  private async renderRegisterPage(url: URL, env: Env) {
    const appName = url.searchParams.get('app')!;
    if (!appName) return new Response('Insert an app', { status: 400 });
    const app = this.appsList[appName];
    if (!app) return new Response('Invalid app', { status: 400 });
    return new Response(registerPage(app), { headers: { 'Content-Type': 'text/html' } });
  }

  private async handleRegister(request: Request, env: Env) {
    const { email, password, app } = Object.fromEntries(await request.formData() as any);
    const db = env.USERS_DB;
    // check existing user
    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{id:string}>();
    if (existing) return new Response(JSON.stringify({ error: 'User already exists' }), { status: 409, headers: { 'Content-Type': 'application/json' } });
    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    // insert new user
    await db.prepare('INSERT INTO users (id, email, password, role) VALUES (?, ?, ?, ?)')
      .bind(id, email, hashed, 'user').run();
    // issue tokens
    const { privateKey } = await this.getKeys(env);
    const accessJti = uuidv4();
    const accessToken = await new SignJWT({ sub: id, role: 'user', jti: accessJti })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setExpirationTime('90d')
      .sign(privateKey);
    await db.prepare('INSERT INTO tokens (jti, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(accessJti, id, Math.floor(Date.now()/1000) + 90*24*3600).run();
    // redirect to app
    const appObj = this.appsList[app];
    if (!appObj) return new Response('Invalid app', { status: 400 });
    const redirectUrl = new URL(appObj.redirect_url);
    redirectUrl.searchParams.set('access_token', accessToken);
    return new Response(JSON.stringify({ redirect: redirectUrl.toString() }), { headers: { 'Content-Type': 'application/json' } });
  }

  private async handlePublicKey() {
    // Return the RSA public key for JWT verification
	const publicKey = await this.getPublicKey();
    return new Response(publicKey, {
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  async getPublicKey() {
	return this.env.PUBLIC_KEY;
  }

    /**
   * 
   * @param token Access Token JWT
   * @param env access to the environment variables
   * @returns true if the token is valid, false otherwise
   * @description This function verifies the JWT using the public key, if it is not expired and not revoked on the database
   */
    async validateSSO(token: string, env: Env) {
      try {
        // Get the public key from the environment
        const { publicKey } = await this.getKeys(env);
        // Verify the JWT using the public key
        const { payload } = await jwtVerify(token, publicKey, { algorithms: ['RS256'] });
        // Check if the token is expired
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
          return false;
        }
        // Check if the token is revoked
        const db = env.USERS_DB;
        console.log({token, payload, publicKey})
        const tok = await db.prepare('SELECT revoked FROM tokens WHERE jti = ?').bind(payload.jti).first<{revoked:number}>();
        if (!tok || tok.revoked) {
          return false;
        }
        // Check if the token is valid
        if (!payload.sub || !payload.jti) {
          return false;
        }
  
        // Check if the token is valid for the user
        const user = await db.prepare('SELECT id FROM users WHERE id = ?').bind(payload.sub).first<{id:string}>();
        if (!user) {
          return false;
        }
        
        return true;
      } catch(e) {
        console.error(e);
        return false;
      }
    }

  async validate(token: string) {
		try {
			const secretNullable = (await this.env.USERS_KV.get('secret')) as string;
			const valid = await jwt.verify(token, secretNullable, { algorithm: 'HS256' });
			return valid;
		} catch (error) {
      return false;
		}
	}
}

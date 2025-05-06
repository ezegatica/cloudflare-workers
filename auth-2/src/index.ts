import { WorkerEntrypoint } from 'cloudflare:workers';
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import qs from 'qs';
import { loginPage, registerPage } from './templates';
import appsList from './apps.json';
import { AppListItem } from './interfaces';
import jwt from '@tsndr/cloudflare-worker-jwt';
import UserRouter from './users.handler';
import forge from 'node-forge';

export default class AuthWorker extends WorkerEntrypoint<Env> {
	private appsList: Record<string, AppListItem> = appsList;
	private usersRouter = new UserRouter(this);
	private timestampThreshold = 5; // Allow 5 seconds difference
	private readonly cookieMaxAge = 90 * 24 * 3600;

	/**
	 * Decrypts encrypted data using private key
	 * @param encryptedData The RSA encrypted data
	 * @returns Decrypted data as string
	 */
	private async decryptData(encryptedData: string): Promise<string> {
		try {
			// Using node-forge for RSA decryption
			const privateKeyPem = this.env.PRIVATE_KEY_SECRET;
			const forgePrivateKey = forge.pki.privateKeyFromPem(privateKeyPem);
			
			// JSEncrypt returns base64-encoded data
			try {
				// Try with PKCS#1 v1.5 padding first (most commonly used by JSEncrypt)
				return forgePrivateKey.decrypt(forge.util.decode64(encryptedData), 'RSAES-PKCS1-V1_5');
			} catch (innerError) {
				console.log("First decryption method failed, trying RSA-OAEP", innerError);
				
				// If the first method fails, try with RSA-OAEP
				return forgePrivateKey.decrypt(forge.util.decode64(encryptedData), 'RSA-OAEP');
			}
		} catch (error) {
			console.error('Decryption error:', error);
			throw new Error('Failed to decrypt data');
		}
	}

	/**
	 * Validates the timestamp is within threshold
	 * @param timestamp The timestamp to validate
	 * @returns True if valid, false otherwise
	 */
	private validateTimestamp(timestamp: string): boolean {
		const now = Math.floor(Date.now() / 1000);
		const ts = parseInt(timestamp, 10);
		
		if (isNaN(ts)) return false;
		
		const diff = Math.abs(now - ts);
		return diff <= this.timestampThreshold;
	}

	/**
	 * Creates and stores a JWT token for a user
	 * @param userId The user ID
	 * @param userRole The user role
	 * @returns The signed JWT token
	 */
	private async createAndStoreToken(userId: string, userRole: string): Promise<string> {
		const { privateKey } = await this.getKeys();
		const accessJti = uuidv4();
		const accessToken = await new SignJWT({ sub: userId, role: userRole, jti: accessJti,  })
			.setProtectedHeader({ alg: 'RS256', typ: 'JWT',
				x5t: 'sha256', // Specify the x5t header with the SHA-256 thumbprint}
				x5u: 'https://sso.eze.net.ar/cert.pem', // URL to the public key
			 })
			.setIssuedAt()
			.setExpirationTime('90d')
			.sign(privateKey);

		// Store token in database
		const expiresAt = Math.floor(Date.now() / 1000) + this.cookieMaxAge;
		await this.env.USERS_DB.prepare('INSERT INTO tokens (jti, user_id, expires_at) VALUES (?, ?, ?)')
			.bind(accessJti, userId, expiresAt)
			.run();

		return accessToken;
	}

	/**
	 * Verifies a JWT token with flexible algorithm support
	 * @param token The JWT token to verify
	 * @param options Additional verification options
	 * @returns Result object with validation status and payload if valid
	 */
	public async verifyToken(
		token: string,
		options: {
			algorithm: 'RS256' | 'HS256';
			checkRevocation?: boolean;
			checkUser?: boolean;
			checkApp?: string;
		}
	): Promise<{ valid: boolean; payload?: any }> {
		try {
			let payload: any;

			// Verify token signature based on algorithm
			if (options.algorithm === 'RS256') {
				const { publicKey } = await this.getKeys();
				try {
					const result = await jwtVerify(token, publicKey, { algorithms: ['RS256'] });
					payload = result.payload;
				} catch (e) {
					console.error(`Token signature verification failed (RS256): ${JSON.stringify(e)}`);
					return { valid: false };
				}
			} else if (options.algorithm === 'HS256') {
				const secretNullable = (await this.env.USERS_KV.get('secret')) as string;
				try {
					const valid = await jwt.verify(token, secretNullable, { algorithm: 'HS256' });
					if (!valid) {
						console.error('Token signature verification failed (HS256)');
						return { valid: false };
					}
					payload = jwt.decode(token).payload;
				} catch (e) {
					console.error(`Token signature verification failed (HS256): ${JSON.stringify(e)}`);
					return { valid: false };
				}
			} else {
				console.error(`Invalid algorithm specified: ${options.algorithm}`);
				return { valid: false };
			}

			// Check token expiration
			if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
				console.error(`Token expired: exp=${payload.exp}, now=${Math.floor(Date.now() / 1000)}`);
				return { valid: false };
			}

			// Check token revocation if requested
			if (options.checkRevocation && payload.jti) {
				const db = this.env.USERS_DB;
				const tok = await db.prepare('SELECT revoked FROM tokens WHERE jti = ?').bind(payload.jti).first<{ revoked: number }>();
				if (!tok) {
					console.error(`Token not found in database: jti=${payload.jti}`);
					return { valid: false };
				}
				if (tok.revoked) {
					console.error(`Token has been revoked: jti=${payload.jti}`);
					return { valid: false };
				}
			}

			// Check if the token is valid for the user
			if (options.checkUser && payload.sub) {
				const db = this.env.USERS_DB;
				const user = await db.prepare('SELECT id FROM users WHERE id = ?').bind(payload.sub).first<{ id: string }>();
				if (!user) {
					console.error(`User not found in database: sub=${payload.sub}`);
					return { valid: false };
				}
			}

			// Check if the token is valid for a specific app
			if (options.checkApp && payload.role) {
				const app = this.appsList[options.checkApp];
				if (!app) {
					console.error(`App not found: ${options.checkApp}`);
					return { valid: false };
				}

				if (app.admin_only && (!payload.role || payload.role !== 'admin')) {
					console.error(`User does not have admin role required by app: user_role=${payload.role}, app=${options.checkApp}`);
					return { valid: false };
				}
			}

			return { valid: true, payload };
		} catch (e) {
			console.error(`Unexpected error during token verification: ${JSON.stringify(e)}`);
			return { valid: false };
		}
	}

	/**
	 * Creates a JSON response with appropriate headers
	 */
	public createJsonResponse(data: any, status: number = 200): Response {
		return new Response(JSON.stringify(data), {
			status,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	/**
	 * Creates an error response with appropriate status code and format
	 */
	public createErrorResponse(message: string, status: number = 400): Response {
		console.error(message);
		return this.createJsonResponse({ error: message }, status);
	}

	/**
	 * Creates a redirect response with token in query params
	 */
	public createTokenRedirectResponse(redirectUrl: URL, accessToken: string): Response {
		redirectUrl.searchParams.set('access_token', accessToken);
		const body = { redirect: redirectUrl.toString(), access_token: accessToken };
		const res = new Response(JSON.stringify(body), {
			status: 200,
			headers: { 'Content-Type': 'application/json' }
		});
		res.headers.set('Set-Cookie', `access_token=${accessToken}; HttpOnly; Path=/; Max-Age=${this.cookieMaxAge}; SameSite=Lax`);
		return res;
	}

	async fetch(request: Request) {
		const url = new URL(request.url);
		if (url.pathname === '/') return new Response('Hello World!');
		if (url.pathname === '/login' && request.method === 'GET') {
			const cookieHeader = request.headers.get('Cookie') || '';
			const match = /(?:^|; )access_token=([^;]+)/.exec(cookieHeader);
			if (match) {
				const token = match[1];
				const appName = url.searchParams.get('app');
				if (appName) {
					const { valid } = await this.verifyToken(token, {
						algorithm: 'RS256',
						checkRevocation: true,
						checkUser: true,
						checkApp: appName
					});
					if (valid) {
						const app = this.appsList[appName];
						const redirectUrl = new URL(app.redirect_url);
						redirectUrl.searchParams.set('access_token', token);
						return new Response(null, { status: 302, headers: { 'Location': redirectUrl.toString() } });
					}
				}
			}
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
			return this.renderRegisterPage(url);
		}
		if (url.pathname === '/register' && request.method === 'POST') {
			return this.handleRegister(request, this.env);
		}
		if (url.pathname === '/public-key' && request.method === 'GET') {
			return this.handlePublicKey();
		}
		if (url.pathname === '/cert.pem' && request.method === 'GET') {
			return this.handleCert();
		}
		if (url.pathname === '/validate' && request.method === 'POST') {
			const { token } = (await request.json()) as { token: string };
			if (!token) return this.createErrorResponse('Missing token', 400);

			const appName = url.searchParams.get('app');
			if (!appName) return this.createErrorResponse('Missing app', 400);
			const valid = await this.validateSSO(token, appName);
			return this.createJsonResponse({ valid });
		}
		if (url.pathname.startsWith('/users')) {
			return this.usersRouter.handle(request, this.env)
		}
		return new Response('Not Found', { status: 404 });
	}

	private async handleCert() {
		const certPem = this.env.CERT_PEM;
		if (!certPem) return new Response('Certificate not found', { status: 404 });
		return new Response(certPem, {
			headers: { 'Content-Type': 'text/plain' },
		});
	}

	private async getKeys() {
		const privPem = this.env.PRIVATE_KEY_SECRET; // private key from secret binding
		const pubPem = this.env.PUBLIC_KEY;
		const privateKey = await importPKCS8(privPem, 'RS256');
		const publicKey = await importSPKI(pubPem, 'RS256');
		return { privateKey, publicKey };
	}

	private async renderLoginPage(url: URL, env: Env) {
		const appName = url.searchParams.get('app')!;
		if (!appName) return new Response('Insert an app', { status: 400 });
		const app = this.appsList[appName];
		if (!app) return new Response('Invalid app', { status: 400 });
		return new Response(loginPage(app, env.PUBLIC_KEY), { headers: { 'Content-Type': 'text/html' } });
	}

	private async handleLogin(request: Request, env: Env) {
		const formData = await request.formData();
		const email = formData.get('email') as string;
		const encryptedPassword = formData.get('encryptedPassword') as string;
		const timestamp = formData.get('timestamp') as string;
		const app = formData.get('app') as string;
		
		const appObj = this.appsList[app];
		if (!appObj) return this.createErrorResponse('Invalid app', 400);

		// Validate timestamp from form data
		if (!this.validateTimestamp(timestamp)) {
			return this.createErrorResponse('Request expired or invalid timestamp', 400);
		}

		// Decrypt the data (now timestamp|password)
		let decryptedData;
		try {
			decryptedData = await this.decryptData(encryptedPassword);
		} catch (error) {
			return this.createErrorResponse('Invalid encrypted data', 400);
		}

		// Split decrypted data on first '|' occurrence - timestamp is first, password may contain pipe characters
		const firstPipeIndex = decryptedData.indexOf('|');
		if (firstPipeIndex === -1) {
			return this.createErrorResponse('Malformed encrypted data', 400);
		}
		
		const embeddedTimestamp = decryptedData.substring(0, firstPipeIndex);
		const password = decryptedData.substring(firstPipeIndex + 1);
		
		// Validate embedded timestamp matches the form timestamp and is within threshold
		if (embeddedTimestamp !== timestamp || !this.validateTimestamp(embeddedTimestamp)) {
			return this.createErrorResponse('Security validation failed', 400);
		}

		const db = env.USERS_DB;
		const userRes = await db
			.prepare('SELECT id, email, password, role FROM users WHERE email = ?')
			.bind(email)
			.first<{ id: string; email: string; password: string; role: string }>();
		if (!userRes) return this.createErrorResponse('Invalid credentials', 401);

		const match = await bcrypt.compare(password, userRes.password);
		if (!match) return this.createErrorResponse('Invalid credentials', 401);

		if (appObj.admin_only && userRes.role !== 'admin') {
			return this.createErrorResponse('Admin access required', 403);
		}

		// Use the unified token creation method
		const accessToken = await this.createAndStoreToken(userRes.id, userRes.role);

		// Use the redirect helper
		const redirectUrl = new URL(appObj.redirect_url);
		return this.createTokenRedirectResponse(redirectUrl, accessToken);
	}

	private async handleRevoke(request: Request, env: Env) {
		const { access_token } = (await request.json()) as { access_token: string };

    // Use the unified verification method
		const { valid, payload } = await this.verifyToken(access_token, {
			algorithm: 'RS256',
      checkRevocation: true,
      checkUser: true,
		});

		if (!valid || !payload || !payload.jti) {
			return this.createErrorResponse('Invalid token', 400);
		}

		const db = env.USERS_DB;
		const res = await db.prepare('UPDATE tokens SET revoked = 1 WHERE jti = ?').bind(payload.jti).run();
		if (res.success) {
      return this.createJsonResponse({ message: 'Token revoked' });
    } 
		return this.createErrorResponse('Failed to revoke', 500);
	}

	private async handleGoogleAuth(url: URL, env: Env) {
		const appName = url.searchParams.get('app');
		if (!appName) return new Response('Invalid app', { status: 400 });
		const app = this.appsList[appName];
		if (!app) return new Response('Invalid app', { status: 400 });
		const state = uuidv4();
		await env.USERS_KV.put(`oauth_state_${state}`, appName as string, { expirationTtl: 300 });
		const params = qs.stringify({
			response_type: 'code',
			client_id: env.GOOGLE_CLIENT_ID,
			redirect_uri: env.GOOGLE_REDIRECT_URI,
			scope: 'openid email profile',
			state,
		});
		return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, 302);
	}

	private async handleGoogleCallback(url: URL, env: Env) {
		const code = url.searchParams.get('code');
		const state = url.searchParams.get('state');
		if (!code || !state) return this.createErrorResponse('Missing code/state', 400);

		const appName = await env.USERS_KV.get(`oauth_state_${state}`);
		if (!appName) return this.createErrorResponse('Invalid state', 400);
		await env.USERS_KV.delete(`oauth_state_${state}`);

		// Exchange code
		const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: qs.stringify({
				code,
				client_id: env.GOOGLE_CLIENT_ID,
				client_secret: env.GOOGLE_CLIENT_SECRET,
				redirect_uri: env.GOOGLE_REDIRECT_URI,
				grant_type: 'authorization_code',
			}),
		});
		const tokenJson = (await tokenRes.json()) as { access_token: string; id_token?: string };
		const userinfoRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
			headers: { Authorization: `Bearer ${tokenJson.access_token}` },
		});
		const { sub: googleId, email } = (await userinfoRes.json()) as any;

		const db = env.USERS_DB;
		let user = await db
			.prepare('SELECT id, role, password FROM users WHERE google_id = ?')
			.bind(googleId)
			.first<{ id: string; role: string; password?: string }>();
		if (user && user.password) return this.createErrorResponse('Account uses password login', 400);

		if (!user) {
			const id = uuidv4();
			await db.prepare('INSERT INTO users (id, email, google_id, role) VALUES (?, ?, ?, ?)').bind(id, email, googleId, 'user').run();
			user = { id, role: 'user' } as any;
		}

		// Use the unified token creation method
		const accessToken = await this.createAndStoreToken(user!.id, user!.role);

		// Redirect back to app
		const app = this.appsList[appName];
		if (!app) return this.createErrorResponse('Invalid app', 400);

		if (app.admin_only && (!user || (user && user.role !== 'admin'))) {
			return this.createErrorResponse('Admin access required', 403);
		}

		const redirectUrl = new URL(app.redirect_url);
		redirectUrl.searchParams.set('access_token', accessToken);
		return new Response(null, {
			status: 302,
			headers: {
				'Location': redirectUrl.toString(),
				'Set-Cookie': `access_token=${accessToken}; HttpOnly; Path=/; Max-Age=${this.cookieMaxAge}; SameSite=Lax`
			}
		});
	}

	private async renderRegisterPage(url: URL) {
		const appName = url.searchParams.get('app')!;
		if (!appName) return new Response('Insert an app', { status: 400 });
		const app = this.appsList[appName];
		if (!app) return new Response('Invalid app', { status: 400 });
		return new Response(registerPage(app, this.env.PUBLIC_KEY), { headers: { 'Content-Type': 'text/html' } });
	}

	private async handleRegister(request: Request, env: Env) {
		const formData = await request.formData();
		const email = formData.get('email') as string;
		const encryptedPassword = formData.get('encryptedPassword') as string;
		const timestamp = formData.get('timestamp') as string;
		const app = formData.get('app') as string;

		const appObj = this.appsList[app];
		if (!appObj) return this.createErrorResponse('Invalid app', 400);

		if (appObj.admin_only) {
			return this.createErrorResponse('Admin access required', 403);
		}

		// Validate timestamp from form data
		if (!this.validateTimestamp(timestamp)) {
			return this.createErrorResponse('Request expired or invalid timestamp', 400);
		}

		// Decrypt the data (now timestamp|password)
		let decryptedData;
		try {
			decryptedData = await this.decryptData(encryptedPassword);
		} catch (error) {
			return this.createErrorResponse('Invalid encrypted data', 400);
		}

		// Split decrypted data on first '|' occurrence - timestamp is first, password may contain pipe characters
		const firstPipeIndex = decryptedData.indexOf('|');
		if (firstPipeIndex === -1) {
			return this.createErrorResponse('Malformed encrypted data', 400);
		}
		
		const embeddedTimestamp = decryptedData.substring(0, firstPipeIndex);
		const password = decryptedData.substring(firstPipeIndex + 1);
		
		// Validate embedded timestamp matches the form timestamp and is within threshold
		if (embeddedTimestamp !== timestamp || !this.validateTimestamp(embeddedTimestamp)) {
			return this.createErrorResponse('Security validation failed', 400);
		}

		const db = env.USERS_DB;

		// Check existing user
		const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{ id: string }>();
		if (existing) return this.createErrorResponse('User already exists', 409);

		const hashed = await bcrypt.hash(password, 10);
		const id = uuidv4();

		// Insert new user
		await db.prepare('INSERT INTO users (id, email, password, role) VALUES (?, ?, ?, ?)').bind(id, email, hashed, 'user').run();

		// Use the unified token creation method
		const accessToken = await this.createAndStoreToken(id, 'user');

		const redirectUrl = new URL(appObj.redirect_url);
		return this.createTokenRedirectResponse(redirectUrl, accessToken);
	}

	private async handlePublicKey() {
		// Return the RSA public key for JWT verification
		const publicKey = this.getPublicKey();
		return new Response(publicKey, {
			headers: { 'Content-Type': 'text/plain' },
		});
	}

	getPublicKey() {
		return this.env.PUBLIC_KEY;
	}

	/**
	 * @param token Access Token JWT
	 * @param appName The application name to validate against
	 * @returns true if the token is valid, false otherwise
	 * @description Verifies JWT using public key and checks validity against app requirements
	 */
	async validateSSO(token: string, appName: string) {
		const result = await this.verifyToken(token, {
			algorithm: 'RS256',
			checkRevocation: true,
			checkUser: true,
			checkApp: appName,
		});

		return result.valid;
	}

	/**
	 * Legacy validation method for HS256 tokens
	 * @param token The token to validate
	 * @returns Whether the token is valid
	 */
	async validate(token: string) {
		const result = await this.verifyToken(token, {
			algorithm: 'HS256',
		});

		return result.valid;
	}
}

import { Router } from "@tsndr/cloudflare-worker-router";
import AuthWorker from ".";
import { UnauthorizedException } from "./exceptions";



export default class UserRouter{
    private router = new Router<Env>();
    
    constructor(
        private readonly app: AuthWorker
    ){
       this.createMiddlewares()
       this.createRoutes();
    }

    public handle(req: Request, env: Env): Promise<Response> {
        return this.router.handle(new Request(req.url.replace('/users', ''), req), env);
    }

    private createRoutes() {
        this.router.get('/', async ({req, env}) => {
            const query = await env.USERS_DB.prepare(
                'SELECT u.id, u.email, u.role, ' +
                'CASE ' +
                'WHEN u.google_id IS NOT NULL THEN \'google\' ' +
                'WHEN u.password IS NOT NULL THEN \'password\' ' +
                'ELSE NULL ' +
                'END AS loginMethod ' +
                'FROM users u'
            ).all();
            
            if (!query.success) {
                return this.app.createErrorResponse(`Failed to fetch users from database: ${query?.error}`, 500);
            }
            if (query.results.length === 0) {
                return this.app.createErrorResponse('No users found', 404);
            }
            return Response.json(query.results);
        });

        this.router.get('/:id/tokens', async ({req, env}) => {
            const id = req.params.id;
            const query = await env.USERS_DB.prepare(
                'SELECT * FROM tokens WHERE user_id = ?'
            ).bind(id).all();
            
            if (!query.success) {
                return this.app.createErrorResponse(`Failed to fetch tokens from database: ${query?.error}`, 500);
            }
            if (query.results.length === 0) {
                return this.app.createErrorResponse('No tokens found', 404);
            }
            return Response.json(query.results);
        });
    }

    private createMiddlewares() {
        this.router.use(async ({ env, req }) => {
            try {
                const header = req.headers.get('Authorization');
                const token = header?.split(' ')[1];
                if (!token) {
                    console.warn('No token provided');
                    throw new UnauthorizedException();
                }
                const isValidToken = await this.app.verifyToken(token, {
                    algorithm: 'RS256',
                    checkRevocation: true,
                    checkUser: true,
                    checkApp: 'dashboard'
                });
                if (!isValidToken) {
                    console.warn('Invalid token', token);
                    throw new UnauthorizedException();
                }
            } catch (error) {
                console.error(error);
                if (error instanceof Response) {
                    return this.app.createErrorResponse(error.statusText, error.status);
                }
                return this.app.createErrorResponse("Unknwown error", 500);
            }
        });
        
    }
};
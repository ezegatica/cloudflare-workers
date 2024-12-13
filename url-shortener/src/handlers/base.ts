export abstract class BaseHandler {
constructor(protected readonly request: Request, protected readonly env: Env, protected readonly ctx: ExecutionContext) {}
  abstract fetch(): Promise<Response>;
}
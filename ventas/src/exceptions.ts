export class UnauthorizedException extends Response {
  constructor() {
    super("Token invalido", {
      status: 401,
      headers: {
        "Content-Type": "text/plain",
      },
    });
  }
}

export class MongoAuthenticationException extends Response {
  constructor() {
    super("Error de autenticación con MongoDB", {
      status: 500,
      headers: {
        "Content-Type": "text/plain",
      },
    });
  }
}

export class WrongProtocolException extends Response {
  constructor() {
    super("Only HTTPS connections are allowed", {
      status: 403,
      headers: {
        "Content-Type": "text/plain",
      },
    });
  }
}

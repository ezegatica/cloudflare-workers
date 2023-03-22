export class LoginFailedException extends Response {
  constructor() {
    super("Login failed", {
      status: 401,
      headers: {
        "Content-Type": "text/plain",
      },
    });
  }
}

export class WrongMethodException extends Response {
  constructor() {
    super("Only POST requests are allowed", {
      status: 405,
      headers: {
        "Content-Type": "text/plain",
      },
    });
  }
}

export class NotFoundException extends Response {
  constructor() {
    super("Could not find the specified resource", {
      status: 404,
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

export class EmptyBodyException extends Response {
  constructor() {
    super("No body was specified", {
      status: 400,
      headers: {
        "Content-Type": "text/plain",
      },
    });
  }
}

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
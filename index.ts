/**
 * The core server that runs on a Cloudflare worker.
 */

import { Router } from "itty-router";
import { AuthErrorResponse, InternalError } from "./src/errors";
import v2Router from "./src/router";
import { authenticationMethodFromEnv } from "./src/authentication-method";
import type { Authenticator } from "./src/auth";
import { Registry } from "./src/registry/registry";
import { R2Registry } from "./src/registry/r2";

// A full compatibility mode means that the r2 registry will try its best to
// help the client on the layer push. See how we let the client push layers with chunked uploads for more information.
type PushCompatibilityMode = "full" | "none";

export interface Env {
  REGISTRY: R2Bucket;
  ENVIRONMENT: string;
  JWT_REGISTRY_TOKENS_PUBLIC_KEY?: string;
  USERNAME?: string;
  PASSWORD?: string;
  READONLY_USERNAME?: string;
  READONLY_PASSWORD?: string;
  PUSH_COMPATIBILITY_MODE?: PushCompatibilityMode;
  REGISTRIES_JSON?: string; // should be in the format of RegistryConfiguration[];
  // "true" lets requests without credentials pull (GET/HEAD); pushing still needs USERNAME/PASSWORD.
  ALLOW_ANONYMOUS_PULL?: string;
  REGISTRY_CLIENT: Registry;
}

const router = Router();

/**
 * V2 Api
 */
router.all("/v2/*", v2Router.fetch);

router.all("*", () => new Response("Not Found.", { status: 404 }));

export default {
  async fetch(request: Request, env: Env, context?: ExecutionContext) {
    if (!ensureConfig(env)) {
      return new AuthErrorResponse(request);
    }

    const authMethod = await authenticationMethodFromEnv(env);
    if (!authMethod) {
      return new AuthErrorResponse(request);
    }

    if (env.ALLOW_ANONYMOUS_PULL === "true") {
      if (new URL(request.url).pathname === TOKEN_PATH) {
        return issueToken(request, authMethod);
      }
      request = fromBearerToken(request);
      if (isAnonymousPing(request)) {
        return new Response("{}", { headers: { "content-type": "application/json" } });
      }
    }

    const credentials = isAnonymousPull(request, env)
      ? { verified: true, payload: null }
      : await authMethod.checkCredentials(request);
    if (!credentials.verified) {
      console.warn(`Not Authorized. authmode=${authMethod.authmode}. verified=false`);
      return withChallenge(new AuthErrorResponse(request), request, env);
    }

    env.REGISTRY_CLIENT = new R2Registry(env);
    try {
      // Dispatch the request to the appropriate route
      const res = await router.fetch(request, env, context);
      return withChallenge(res, request, env);
    } catch (err) {
      if (err instanceof Response) {
        console.warn(`${request.method} ${err.status} ${err.url}`);
        return err;
      }

      // Unexpected error
      if (err instanceof Error) {
        console.error(
          "An error has been thrown by the router:\n",
          `${err.name}: ${err.message}: ${err.cause}: ${err.stack}`,
        );
        return new InternalError();
      }

      console.error(
        "An error has been thrown and is neither a Response or an Error, JSON.stringify() =",
        JSON.stringify(err),
      );
      return new InternalError();
    }
  },
} satisfies ExportedHandler<Env>;

/**
 * A request with no Authorization header that only reads, on a registry with ALLOW_ANONYMOUS_PULL.
 *
 * A bare GET /v2/ is left out on purpose: its 401 challenge is how docker, crane and friends learn
 * that this registry takes credentials. Without it a logged-in client never sends them and every
 * push fails. The challenge is the Bearer token flow (see issueToken), because docker with no
 * credentials cannot answer a Basic one. podman may still send Basic auth with an empty username
 * and password; that counts as anonymous too. /v2/_catalog is left out, so anonymous clients
 * cannot list every repository.
 */
const isAnonymousPull = (request: Request, env: Env): boolean => {
  if (env.ALLOW_ANONYMOUS_PULL !== "true" || !hasNoCredentials(request)) {
    return false;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return false;
  }
  const path = new URL(request.url).pathname;
  return path.startsWith("/v2/") && path !== "/v2/" && !path.startsWith("/v2/_catalog");
};

const hasNoCredentials = (request: Request): boolean => {
  const authorization = request.headers.get("Authorization");
  if (authorization === null) {
    return true;
  }
  const [scheme, encoded = ""] = authorization.trim().split(/\s+/);
  if (scheme !== "Basic") {
    return false;
  }
  try {
    return ["", ":"].includes(atob(encoded));
  } catch {
    return false;
  }
};

const ensureConfig = (env: Env): boolean => {
  if (!env.REGISTRY) {
    console.error(
      "env.REGISTRY is not setup. Please setup an R2 bucket and add the binding in your wrangler config file. Try 'npx wrangler --env production r2 bucket create r2-registry'",
    );
    return false;
  }

  return true;
};

/**
 * Docker cannot pull anonymously from a registry that challenges with Basic: with no credentials
 * for the host it fails with "no basic auth credentials" instead of retrying without them. So on a
 * registry with ALLOW_ANONYMOUS_PULL the challenge is the token flow Docker Hub uses:
 *
 *   401 WWW-Authenticate: Bearer realm="https://<host>/token",service="<host>"
 *
 * The client then asks GET /token, with its Basic credentials if it has any. Without credentials it
 * gets the pull-only token "anonymous". With valid credentials it gets a token that carries them
 * (TLS only, and only ever handed back to the client that sent them), which fromBearerToken turns
 * back into the Basic header, so every existing credential check still applies. Wrong credentials
 * get a 401, so a bad `docker login` still fails.
 */
const TOKEN_PATH = "/token";
const ANONYMOUS_TOKEN = "anonymous";
const BASIC_TOKEN_PREFIX = "basic.";

const issueToken = async (request: Request, authMethod: Authenticator): Promise<Response> => {
  let token = ANONYMOUS_TOKEN;
  if (!hasNoCredentials(request)) {
    const credentials = await authMethod.checkCredentials(request);
    if (!credentials.verified) {
      return new AuthErrorResponse(request);
    }
    const [, encoded] = (request.headers.get("Authorization") ?? "").trim().split(/\s+/);
    token = BASIC_TOKEN_PREFIX + encoded;
  }
  return Response.json({
    token,
    access_token: token,
    expires_in: 3600,
    issued_at: new Date().toISOString(),
  });
};

const fromBearerToken = (request: Request): Request => {
  const headers = new Headers(request.headers);
  // Only this Worker may set the anonymous marker.
  headers.delete(ANONYMOUS_TOKEN_HEADER);
  const [scheme, token = ""] = (headers.get("Authorization") ?? "").trim().split(/\s+/);
  if (scheme !== "Bearer") {
    return new Request(request, { headers });
  }
  if (token.startsWith(BASIC_TOKEN_PREFIX)) {
    headers.set("Authorization", `Basic ${token.slice(BASIC_TOKEN_PREFIX.length)}`);
  } else if (token === ANONYMOUS_TOKEN) {
    headers.delete("Authorization");
    headers.set(ANONYMOUS_TOKEN_HEADER, "1");
  } else {
    headers.set("Authorization", "Bearer invalid");
  }
  return new Request(request, { headers });
};

// Marks a request that came with the anonymous token, so its /v2/ ping can succeed. A bare /v2/
// with no token at all still gets the challenge, which is how clients discover the token flow.
const ANONYMOUS_TOKEN_HEADER = "X-Monk-Anonymous-Token";

const isAnonymousPing = (request: Request): boolean =>
  request.headers.get(ANONYMOUS_TOKEN_HEADER) === "1" &&
  new URL(request.url).pathname === "/v2/" &&
  (request.method === "GET" || request.method === "HEAD");

const withChallenge = (response: Response, request: Request, env: Env): Response => {
  if (response.status !== 401 || env.ALLOW_ANONYMOUS_PULL !== "true") {
    return response;
  }
  const url = new URL(request.url);
  const headers = new Headers(response.headers);
  headers.set("WWW-Authenticate", `Bearer realm="${url.origin}${TOKEN_PATH}",service="${url.host}"`);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
};

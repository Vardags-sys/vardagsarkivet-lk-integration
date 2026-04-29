import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import axios from "axios";

const app = Fastify({ logger: true });

const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.API_KEY;

const LK_BASE_URL = process.env.LK_BASE_URL || "https://my.lk.nu";
const LK_EMAIL = process.env.LK_EMAIL;
const LK_PASSWORD = process.env.LK_PASSWORD;

const LK_LOGIN_PATH = process.env.LK_LOGIN_PATH || "/login";
const LK_USERNAME_FIELD = process.env.LK_USERNAME_FIELD || "email";
const LK_PASSWORD_FIELD = process.env.LK_PASSWORD_FIELD || "password";

const LK_THERMOSTAT_COUNT = Number(process.env.LK_THERMOSTAT_COUNT || 12);
const LK_THERMOSTAT_PATH =
  process.env.LK_THERMOSTAT_PATH || "/thermostat.json?tid={tid}";

const LK_INSECURE_TLS = process.env.LK_INSECURE_TLS === "true";

if (LK_INSECURE_TLS) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

if (!API_KEY) {
  throw new Error("Missing API_KEY environment variable");
}

if (!LK_EMAIL || !LK_PASSWORD) {
  throw new Error("Missing LK_EMAIL or LK_PASSWORD environment variables");
}

await app.register(cors, {
  origin: true,
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
});

app.addHook("onRequest", async (request, reply) => {
  if (request.url === "/health") return;

  const auth = request.headers.authorization || "";
  const expected = `Bearer ${API_KEY}`;

  if (auth !== expected) {
    return reply.code(401).send({
      ok: false,
      error: "unauthorized",
      message: "Missing or invalid Bearer token",
    });
  }
});

class SimpleCookieJar {
  constructor() {
    this.cookies = new Map();
  }

  addFromSetCookie(setCookieHeader) {
    if (!setCookieHeader) return;

    const cookies = Array.isArray(setCookieHeader)
      ? setCookieHeader
      : [setCookieHeader];

    for (const cookieLine of cookies) {
      if (!cookieLine || typeof cookieLine !== "string") continue;

      const firstPart = cookieLine.split(";")[0];
      const equalsIndex = firstPart.indexOf("=");

      if (equalsIndex <= 0) continue;

      const name = firstPart.slice(0, equalsIndex).trim();
      const value = firstPart.slice(equalsIndex + 1).trim();

      if (name) {
        this.cookies.set(name, value);
      }
    }
  }

  getHeader() {
    return [...this.cookies.entries()]
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
  }

  count() {
    return this.cookies.size;
  }

  names() {
    return [...this.cookies.keys()];
  }
}

function makeUrl(pathOrUrl) {
  if (pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")) {
    return pathOrUrl;
  }

  const base = LK_BASE_URL.replace(/\/+$/, "");
  const path = pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`;

  return `${base}${path}`;
}

async function lkRequest(jar, options) {
  const {
    method = "GET",
    path,
    data = undefined,
    headers = {},
    maxRedirects = 5,
  } = options;

  let currentMethod = method.toUpperCase();
  let currentUrl = makeUrl(path);
  let currentData = data;

  for (let redirect = 0; redirect <= maxRedirects; redirect++) {
    const cookieHeader = jar.getHeader();

    const response = await axios({
      method: currentMethod,
      url: currentUrl,
      data: currentData,
      timeout: 20000,
      maxRedirects: 0,
      validateStatus: () => true,
      headers: {
        "User-Agent": "Vardagsarkivet-LK-Integration/0.2",
        Accept: "application/json,text/html,*/*",
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        ...headers,
      },
    });

    jar.addFromSetCookie(response.headers["set-cookie"]);

    if (
      [301, 302, 303, 307, 308].includes(response.status) &&
      response.headers.location &&
      redirect < maxRedirects
    ) {
      const nextUrl = new URL(response.headers.location, currentUrl).toString();

      currentUrl = nextUrl;

      if (response.status === 303 || currentMethod === "POST") {
        currentMethod = "GET";
        currentData = undefined;
      }

      continue;
    }

    return response;
  }

  throw new Error("Too many redirects while calling LK");
}

function shortBody(data, limit = 1000) {
  if (data === undefined || data === null) return null;

  if (typeof data === "string") {
    return data.slice(0, limit);
  }

  try {
    return JSON.stringify(data).slice(0, limit);
  } catch {
    return String(data).slice(0, limit);
  }
}

async function loginToLk() {
  const jar = new SimpleCookieJar();

  // First request establishes any anonymous/session cookies.
  await lkRequest(jar, {
    method: "GET",
    path: "/",
  });

  const form = new URLSearchParams();
  form.set(LK_USERNAME_FIELD, LK_EMAIL);
  form.set(LK_PASSWORD_FIELD, LK_PASSWORD);

  const response = await lkRequest(jar, {
    method: "POST",
    path: LK_LOGIN_PATH,
    data: form.toString(),
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: LK_BASE_URL,
      Referer: `${LK_BASE_URL}/`,
    },
  });

  if (response.status >= 400) {
    throw new Error(
      `LK login failed. HTTP ${response.status}: ${shortBody(response.data, 800)}`
    );
  }

  return {
    jar,
    loginStatus: response.status,
    loginContentType: response.headers["content-type"] || null,
    loginSample: shortBody(response.data, 500),
  };
}

function thermostatPath(tid) {
  return LK_THERMOSTAT_PATH.replace("{tid}", encodeURIComponent(String(tid)));
}

function toCelsius(value) {
  if (value === undefined || value === null || value === "") return null;

  const n = Number(value);

  if (Number.isNaN(n)) return null;

  if (Math.abs(n) > 100) return n / 100;

  return n;
}

function normalizeThermostat(tid, raw) {
  const currentTemperature =
    toCelsius(raw.get_room_deg) ??
    toCelsius(raw.current_temp) ??
    toCelsius(raw.currentTemperature) ??
    toCelsius(raw.room_temp) ??
    toCelsius(raw.temperature) ??
    null;

  const setpoint =
    toCelsius(raw.set_room_deg) ??
    toCelsius(raw.setpoint) ??
    toCelsius(raw.target_temp) ??
    toCelsius(raw.targetTemperature) ??
    null;

  return {
    tid,
    name:
      raw.name ??
      raw.room_name ??
      raw.label ??
      raw.description ??
      `Thermostat ${tid}`,
    currentTemperature,
    setpoint,
    battery: raw.battery !== undefined ? Number(raw.battery) : null,
    heating:
      raw.heat_status === true ||
      raw.heat_status === "true" ||
      raw.heat_status === 1 ||
      raw.heat_status === "1" ||
      raw.heating === true ||
      raw.heating === "true",
    raw,
  };
}

app.get("/health", async () => {
  return {
    ok: true,
    service: "vardagsarkivet-lk-integration",
    version: "0.2",
  };
});

app.get("/lk/debug-home", async () => {
  const jar = new SimpleCookieJar();

  const response = await lkRequest(jar, {
    method: "GET",
    path: "/",
  });

  return {
    ok: true,
    baseUrl: LK_BASE_URL,
    status: response.status,
    contentType: response.headers["content-type"] || null,
    cookies: {
      count: jar.count(),
      names: jar.names(),
    },
    sample: shortBody(response.data, 2000),
  };
});

app.get("/lk/debug-login-config", async () => {
  return {
    ok: true,
    baseUrl: LK_BASE_URL,
    loginPath: LK_LOGIN_PATH,
    usernameField: LK_USERNAME_FIELD,
    passwordField: LK_PASSWORD_FIELD,
    thermostatPath: LK_THERMOSTAT_PATH,
    thermostatCount: LK_THERMOSTAT_COUNT,
    insecureTls: LK_INSECURE_TLS,
    emailConfigured: Boolean(LK_EMAIL),
    passwordConfigured: Boolean(LK_PASSWORD),
  };
});

app.get("/lk/test-login", async () => {
  const result = await loginToLk();

  return {
    ok: true,
    baseUrl: LK_BASE_URL,
    loginStatus: result.loginStatus,
    loginContentType: result.loginContentType,
    cookies: {
      count: result.jar.count(),
      names: result.jar.names(),
    },
    message: "Login request completed.",
    sample: result.loginSample,
  };
});

app.get("/lk/thermostats", async () => {
  const { jar } = await loginToLk();

  const thermostats = [];
  const errors = [];

  for (let tid = 1; tid <= LK_THERMOSTAT_COUNT; tid++) {
    try {
      const response = await lkRequest(jar, {
        method: "GET",
        path: thermostatPath(tid),
      });

      if (response.status === 404) {
        continue;
      }

      if (response.status >= 400) {
        errors.push({
          tid,
          status: response.status,
          error: shortBody(response.data, 500),
        });
        continue;
      }

      if (!response.data || typeof response.data !== "object") {
        errors.push({
          tid,
          status: response.status,
          error: "Response was not JSON",
          sample: shortBody(response.data, 500),
        });
        continue;
      }

      thermostats.push(normalizeThermostat(tid, response.data));
    } catch (error) {
      errors.push({
        tid,
        error: error.message,
      });
    }
  }

  return {
    ok: true,
    count: thermostats.length,
    thermostats,
    errors,
  };
});

app.get("/lk/thermostats/:tid", async (request, reply) => {
  const tid = Number(request.params.tid);

  if (!Number.isInteger(tid) || tid < 1) {
    return reply.code(400).send({
      ok: false,
      error: "invalid_thermostat_id",
    });
  }

  const { jar } = await loginToLk();

  const response = await lkRequest(jar, {
    method: "GET",
    path: thermostatPath(tid),
  });

  if (response.status >= 400) {
    return reply.code(response.status).send({
      ok: false,
      error: "lk_request_failed",
      status: response.status,
      body: shortBody(response.data, 500),
    });
  }

  return {
    ok: true,
    thermostat: normalizeThermostat(tid, response.data),
  };
});

app.post("/lk/thermostats/:tid/setpoint", async (request, reply) => {
  return reply.code(501).send({
    ok: false,
    error: "setpoint_not_implemented_yet",
    message:
      "Capture the real LK write request from browser DevTools/HAR, then implement this endpoint safely.",
  });
});

app.setErrorHandler((error, request, reply) => {
  request.log.error(error);

  reply.code(500).send({
    ok: false,
    error: "internal_server_error",
    message: error.message,
  });
});

try {
  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`LK integration service listening on port ${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

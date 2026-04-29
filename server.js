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

const LK_INSECURE_TLS = process.env.LK_INSECURE_TLS === "true";
const LK_LKID_COOKIE = process.env.LK_LKID_COOKIE || "";

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

  set(name, value) {
    if (!name || value === undefined || value === null || value === "") return;

    let cleanValue = String(value).trim();

    // If user pasted "lkid=...; something=...", extract only value.
    const pattern = new RegExp(`${name}=([^;]+)`);
    const match = cleanValue.match(pattern);
    if (match) cleanValue = match[1].trim();

    // LK/Tornado cookies are quoted in the browser.
    if (
      ["lkid", "theemail", "user", "lasttab"].includes(name) &&
      !cleanValue.startsWith('"')
    ) {
      cleanValue = `"${cleanValue}"`;
    }

    this.cookies.set(name, cleanValue);
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
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        Accept: "application/json,text/html,*/*",
        "Accept-Language": "sv,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control": "no-cache",
        Pragma: "no-cache",
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
      currentUrl = new URL(response.headers.location, currentUrl).toString();

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

function createSeededJar() {
  const jar = new SimpleCookieJar();

  jar.set("theemail", LK_EMAIL);
  jar.set("viewport", "796x1121x1.00");

  if (LK_LKID_COOKIE) {
    jar.set("lkid", LK_LKID_COOKIE);
  }

  return jar;
}

async function loginToLk() {
  const jar = createSeededJar();

  await lkRequest(jar, {
    method: "GET",
    path: "/login?next=%2F",
  });

  const form = new URLSearchParams();
  form.set(LK_USERNAME_FIELD, LK_EMAIL);
  form.set(LK_PASSWORD_FIELD, LK_PASSWORD);

  const response = await lkRequest(jar, {
    method: "POST",
    path: LK_LOGIN_PATH,
    data: form.toString(),
    headers: {
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      Origin: LK_BASE_URL,
      Referer: `${LK_BASE_URL}/login?next=%2F`,
      Accept: "*/*",
    },
  });

  if (response.status >= 400) {
    throw new Error(
      `LK login failed. HTTP ${response.status}: ${shortBody(response.data, 800)}`
    );
  }

  if (
    response.data &&
    typeof response.data === "object" &&
    response.data.error &&
    String(response.data.error) !== "0"
  ) {
    throw new Error(`LK login rejected: ${shortBody(response.data, 800)}`);
  }

  return {
    jar,
    loginStatus: response.status,
    loginContentType: response.headers["content-type"] || null,
    loginResponse: response.data,
  };
}

function decodeHexLatin1(hex) {
  if (!hex || typeof hex !== "string") return "";

  try {
    const bytes = hex.match(/.{1,2}/g)?.map((b) => parseInt(b, 16)) || [];
    return Buffer.from(bytes).toString("latin1");
  } catch {
    return hex;
  }
}

function toCelsius(value) {
  if (value === undefined || value === null || value === "") return null;

  const n = Number(value);

  if (Number.isNaN(n)) return null;

  if (Math.abs(n) > 100) return n / 100;

  return n;
}

async function getMainJson() {
  const { jar, loginResponse } = await loginToLk();

  const response = await lkRequest(jar, {
    method: "GET",
    path: `/main.json?_=${Date.now()}`,
    headers: {
      Accept: "*/*",
      Referer: `${LK_BASE_URL}/`,
    },
  });

  if (response.status >= 400) {
    throw new Error(
      `LK main.json failed. HTTP ${response.status}: ${shortBody(
        response.data,
        800
      )}`
    );
  }

  if (!response.data || typeof response.data !== "object") {
    throw new Error(`LK main.json was not JSON: ${shortBody(response.data, 800)}`);
  }

  return {
    raw: response.data,
    loginResponse,
    cookies: {
      count: jar.count(),
      names: jar.names(),
    },
  };
}

function normalizeMainJson(raw) {
  const names = raw.name || [];
  const sectionNames = raw.sect_name || [];
  const active = raw.active || [];
  const getRoomDeg = raw.get_room_deg || [];
  const setRoomDeg = raw.set_room_deg || [];
  const heatStatus = raw.heat_status || [];
  const zoneAlarms = raw.zone_alarms || [];
  const bypassStatus = raw.bypass_status || [];

  const zones = [];

  for (let i = 0; i < names.length; i++) {
    const isActive = String(active[i] || "0") === "1";

    if (!isActive) continue;

    const zone = {
      index: i,
      id: i + 1,
      name: decodeHexLatin1(names[i]),
      currentTemperature: toCelsius(getRoomDeg[i]),
      setpoint: toCelsius(setRoomDeg[i]),
      heating: String(heatStatus[i] || "0") === "1",
      alarm: String(zoneAlarms[i] || "0") !== "0",
      bypass: String(bypassStatus[i] || "0") !== "0",
      raw: {
        name: names[i],
        active: active[i],
        get_room_deg: getRoomDeg[i],
        set_room_deg: setRoomDeg[i],
        heat_status: heatStatus[i],
        zone_alarms: zoneAlarms[i],
        bypass_status: bypassStatus[i],
      },
    };

    zones.push(zone);
  }

  const sections = sectionNames.map((name, index) => ({
    index,
    id: index + 1,
    name: decodeHexLatin1(name),
  }));

  return {
    sections,
    zones,
  };
}

app.get("/health", async () => {
  return {
    ok: true,
    service: "vardagsarkivet-lk-integration",
    version: "0.3-main-json",
  };
});

app.get("/lk/debug-login-config", async () => {
  return {
    ok: true,
    baseUrl: LK_BASE_URL,
    loginPath: LK_LOGIN_PATH,
    usernameField: LK_USERNAME_FIELD,
    passwordField: LK_PASSWORD_FIELD,
    insecureTls: LK_INSECURE_TLS,
    emailConfigured: Boolean(LK_EMAIL),
    passwordConfigured: Boolean(LK_PASSWORD),
    lkidCookieConfigured: Boolean(LK_LKID_COOKIE),
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
    loginResponse: result.loginResponse,
  };
});

app.get("/lk/main", async () => {
  const result = await getMainJson();

  return {
    ok: true,
    cookies: result.cookies,
    data: result.raw,
  };
});

app.get("/lk/zones", async () => {
  const result = await getMainJson();
  const normalized = normalizeMainJson(result.raw);

  return {
    ok: true,
    ...normalized,
  };
});

// Backwards-compatible endpoint for Base44 dashboard.
app.get("/lk/thermostats", async () => {
  const result = await getMainJson();
  const normalized = normalizeMainJson(result.raw);

  return {
    ok: true,
    count: normalized.zones.length,
    thermostats: normalized.zones,
    sections: normalized.sections,
  };
});

app.get("/lk/thermostats/:id", async (request, reply) => {
  const id = Number(request.params.id);

  if (!Number.isInteger(id) || id < 1) {
    return reply.code(400).send({
      ok: false,
      error: "invalid_thermostat_id",
    });
  }

  const result = await getMainJson();
  const normalized = normalizeMainJson(result.raw);
  const thermostat = normalized.zones.find((z) => z.id === id || z.index === id);

  if (!thermostat) {
    return reply.code(404).send({
      ok: false,
      error: "thermostat_not_found",
    });
  }

  return {
    ok: true,
    thermostat,
  };
});

app.post("/lk/thermostats/:id/setpoint", async (request, reply) => {
  return reply.code(501).send({
    ok: false,
    error: "setpoint_not_implemented_yet",
    message:
      "Read support is implemented through main.json. Capture the real LK write request when pressing plus/minus to implement setpoint changes.",
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

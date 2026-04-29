import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import axios from "axios";
import { wrapper } from "axios-cookiejar-support";
import { CookieJar } from "tough-cookie";
import https from "node:https";

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

function createLkClient() {
  const jar = new CookieJar();

  const httpsAgent = new https.Agent({
    rejectUnauthorized: !LK_INSECURE_TLS,
  });

  return wrapper(
    axios.create({
      baseURL: LK_BASE_URL,
      jar,
      withCredentials: true,
      timeout: 20000,
      maxRedirects: 5,
      httpsAgent,
      validateStatus: (status) => status < 500,
      headers: {
        "User-Agent": "Vardagsarkivet-LK-Integration/0.1",
        Accept: "application/json,text/html,*/*",
      },
    })
  );
}

async function loginToLk() {
  const client = createLkClient();

  const form = new URLSearchParams();
  form.set(LK_USERNAME_FIELD, LK_EMAIL);
  form.set(LK_PASSWORD_FIELD, LK_PASSWORD);

  const response = await client.post(LK_LOGIN_PATH, form.toString(), {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: LK_BASE_URL,
      Referer: `${LK_BASE_URL}/`,
    },
  });

  if (response.status >= 400) {
    throw new Error(
      `LK login failed. HTTP ${response.status}: ${String(response.data).slice(0, 500)}`
    );
  }

  return client;
}

function thermostatPath(tid) {
  return LK_THERMOSTAT_PATH.replace("{tid}", encodeURIComponent(String(tid)));
}

function toCelsius(value) {
  if (value === undefined || value === null || value === "") return null;
  const n = Number(value);
  if (Number.isNaN(n)) return null;

  // LK community integrations often show temperatures as hundredths of degrees.
  // Example: 2050 => 20.50 C.
  if (Math.abs(n) > 100) return n / 100;

  return n;
}

function normalizeThermostat(tid, raw) {
  const currentTemperature =
    toCelsius(raw.get_room_deg) ??
    toCelsius(raw.current_temp) ??
    toCelsius(raw.currentTemperature) ??
    toCelsius(raw.room_temp) ??
    toCelsius(raw.temperature);

  const setpoint =
    toCelsius(raw.set_room_deg) ??
    toCelsius(raw.setpoint) ??
    toCelsius(raw.target_temp) ??
    toCelsius(raw.targetTemperature);

  return {
    tid,
    name: raw.name ?? raw.room_name ?? raw.label ?? raw.description ?? `Thermostat ${tid}`,
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
  };
});

app.get("/lk/test-login", async () => {
  await loginToLk();

  return {
    ok: true,
    baseUrl: LK_BASE_URL,
    message: "Login request completed and session cookie jar was created.",
  };
});

app.get("/lk/thermostats", async () => {
  const client = await loginToLk();

  const thermostats = [];
  const errors = [];

  for (let tid = 1; tid <= LK_THERMOSTAT_COUNT; tid++) {
    try {
      const path = thermostatPath(tid);
      const response = await client.get(path);

      if (response.status === 404) {
        continue;
      }

      if (response.status >= 400) {
        errors.push({
          tid,
          status: response.status,
          error: String(response.data).slice(0, 500),
        });
        continue;
      }

      if (!response.data || typeof response.data !== "object") {
        errors.push({
          tid,
          status: response.status,
          error: "Response was not JSON",
          sample: String(response.data).slice(0, 500),
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

  const client = await loginToLk();
  const response = await client.get(thermostatPath(tid));

  if (response.status >= 400) {
    return reply.code(response.status).send({
      ok: false,
      error: "lk_request_failed",
      status: response.status,
      body: String(response.data).slice(0, 500),
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

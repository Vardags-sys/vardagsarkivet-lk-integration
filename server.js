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
const LK_USER_COOKIE = process.env.LK_USER_COOKIE || "";

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

    const pattern = new RegExp(`${name}=([^;]+)`);
    const match = cleanValue.match(pattern);

    if (match) {
      cleanValue = match[1].trim();
    }

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

  delete(name) {
    this.cookies.delete(name);
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
  if (
    pathOrUrl.startsWith("http://") ||
    pathOrUrl.startsWith("https://")
  ) {
    return pathOrUrl;
  }

  const base = LK_BASE_URL.replace(/\/+$/, "");
  const path = pathOrUrl.startsWith("/")
    ? pathOrUrl
    : `/${pathOrUrl}`;

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
        "Accept-Language":
          "sv,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control": "no-cache",
        Pragma: "no-cache",
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        ...headers,
      },
    });

    jar.addFromSetCookie(response.headers["set-cookie"]);

    const isRedirect = [301, 302, 303, 307, 308].includes(
      response.status
    );

    if (
      isRedirect &&
      response.headers.location &&
      redirect < maxRedirects
    ) {
      currentUrl = new URL(
        response.headers.location,
        currentUrl
      ).toString();

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
  if (data === undefined || data === null) {
    return null;
  }

  if (typeof data === "string") {
    return data.slice(0, limit);
  }

  try {
    return JSON.stringify(data).slice(0, limit);
  } catch {
    return String(data).slice(0, limit);
  }
}

function createSeededJar({ includeSavedSession = true } = {}) {
  const jar = new SimpleCookieJar();

  jar.set("theemail", LK_EMAIL);
  jar.set("viewport", "796x1121x1.00");

  if (includeSavedSession) {
    if (LK_LKID_COOKIE) {
      jar.set("lkid", LK_LKID_COOKIE);
    }

    if (LK_USER_COOKIE) {
      jar.set("user", LK_USER_COOKIE);
    }
  }

  return jar;
}

async function loginToLk({ forceLogin = false } = {}) {
  const jar = createSeededJar({
    includeSavedSession: !forceLogin,
  });

  if (!forceLogin && LK_USER_COOKIE && LK_LKID_COOKIE) {
    return {
      jar,
      loginStatus: "cookie-session",
      loginContentType: null,
      loginResponse: {
        msg: "Using pre-authenticated LK cookies from environment variables",
      },
    };
  }

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
      "Content-Type":
        "application/x-www-form-urlencoded; charset=UTF-8",
      Origin: LK_BASE_URL,
      Referer: `${LK_BASE_URL}/login?next=%2F`,
      Accept: "*/*",
    },
  });

  if (response.status >= 400) {
    throw new Error(
      `LK login failed. HTTP ${response.status}: ${shortBody(
        response.data,
        800
      )}`
    );
  }

  if (
    response.data &&
    typeof response.data === "object" &&
    response.data.error &&
    String(response.data.error) !== "0"
  ) {
    throw new Error(
      `LK login rejected: ${shortBody(response.data, 800)}`
    );
  }

  return {
    jar,
    loginStatus: response.status,
    loginContentType:
      response.headers["content-type"] || null,
    loginResponse: response.data,
  };
}

function decodeHexLatin1(hex) {
  if (!hex || typeof hex !== "string") {
    return "";
  }

  try {
    return Buffer.from(hex, "hex").toString("latin1");
  } catch {
    return hex;
  }
}

function encodeHexLatin1(text) {
  if (typeof text !== "string") {
    throw new Error("name must be a string");
  }

  if (text.length > 15) {
    throw new Error("name may not exceed 15 characters");
  }

  return Buffer.from(text, "latin1").toString("hex");
}

function toCelsius(value) {
  if (
    value === undefined ||
    value === null ||
    value === ""
  ) {
    return null;
  }

  const number = Number(value);

  if (Number.isNaN(number)) {
    return null;
  }

  return Math.abs(number) > 100 ? number / 100 : number;
}

function toLkTemp(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    throw new Error("temperature must be numeric");
  }

  const raw =
    Math.abs(number) <= 100
      ? Math.round(number * 100)
      : Math.round(number);

  if (raw < 700 || raw > 4000) {
    throw new Error(
      "temperature must be between 7.0 and 40.0 °C"
    );
  }

  return raw;
}

function toEnabled(value) {
  if (
    value === true ||
    value === 1 ||
    value === "1" ||
    value === "true" ||
    value === "on"
  ) {
    return "1";
  }

  if (
    value === false ||
    value === 0 ||
    value === "0" ||
    value === "false" ||
    value === "off"
  ) {
    return "0";
  }

  throw new Error("enabled must be boolean");
}

function toMinutesFromMidnight(value) {
  if (typeof value === "number") {
    if (value < 0 || value > 1440) {
      throw new Error("time minutes must be 0-1440");
    }

    return Math.round(value);
  }

  if (
    typeof value === "string" &&
    /^\d{1,2}:\d{2}$/.test(value)
  ) {
    const [hours, minutes] = value.split(":").map(Number);
    const totalMinutes = hours * 60 + minutes;

    if (totalMinutes < 0 || totalMinutes > 1440) {
      throw new Error("time must be 00:00-24:00");
    }

    return totalMinutes;
  }

  throw new Error(
    "time must be minutes number or HH:mm string"
  );
}

function normalizePercentToLk(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    throw new Error("percent must be numeric");
  }

  if (number < 0 || number > 100) {
    throw new Error("percent must be 0-100");
  }

  return Math.round(number * 100);
}

function validateTid(id) {
  const tid = Number(id);

  if (!Number.isInteger(tid) || tid < 1 || tid > 64) {
    throw new Error(
      "tid must be an integer between 1 and 64"
    );
  }

  return tid;
}

async function lkUpdate(jar, params) {
  const query = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      query.set(key, String(value));
    }
  }

  query.set("_", String(Date.now()));

  const response = await lkRequest(jar, {
    method: "GET",
    path: `/update.cgi?${query.toString()}`,
    headers: {
      Accept: "*/*",
      Referer: `${LK_BASE_URL}/`,
      "X-Requested-With": "XMLHttpRequest",
    },
  });

  if (response.status >= 400) {
    throw new Error(
      `LK update failed. HTTP ${response.status}: ${shortBody(
        response.data,
        800
      )}`
    );
  }

  return {
    status: response.status,
    params,
    response: response.data,
  };
}

async function requestMainJson(jar) {
  return lkRequest(jar, {
    method: "GET",
    path: `/main.json?_=${Date.now()}`,
    headers: {
      Accept: "*/*",
      Referer: `${LK_BASE_URL}/`,
      "X-Requested-With": "XMLHttpRequest",
    },
  });
}

function isJsonObject(response) {
  return Boolean(
    response &&
      response.data &&
      typeof response.data === "object" &&
      !Buffer.isBuffer(response.data)
  );
}

async function getMainJson() {
  let loginResult = await loginToLk();
  let response = await requestMainJson(loginResult.jar);

  if (response.status >= 400) {
    throw new Error(
      `LK main.json failed. HTTP ${response.status}: ${shortBody(
        response.data,
        800
      )}`
    );
  }

  if (!isJsonObject(response)) {
    app.log.warn(
      {
        status: response.status,
        contentType: response.headers["content-type"] || null,
      },
      "LK saved session returned non-JSON. Retrying with fresh login."
    );

    loginResult = await loginToLk({
      forceLogin: true,
    });

    response = await requestMainJson(loginResult.jar);
  }

  if (response.status >= 400) {
    throw new Error(
      `LK main.json failed after relogin. HTTP ${
        response.status
      }: ${shortBody(response.data, 800)}`
    );
  }

  if (!isJsonObject(response)) {
    const contentType =
      response.headers["content-type"] || "unknown";

    throw new Error(
      `LK main.json was not JSON after relogin. Content-Type ${contentType}: ${shortBody(
        response.data,
        800
      )}`
    );
  }

  return {
    jar: loginResult.jar,
    raw: response.data,
    loginResponse: loginResult.loginResponse,
    cookies: {
      count: loginResult.jar.count(),
      names: loginResult.jar.names(),
    },
  };
}

async function getThermostatJson(id) {
  const tid = validateTid(id);
  let loginResult = await loginToLk();

  let response = await lkRequest(loginResult.jar, {
    method: "GET",
    path: `/thermostat.json?tid=${tid}&_=${Date.now()}`,
    headers: {
      Accept: "*/*",
      Referer: `${LK_BASE_URL}/thermostat.htm?tid=${tid}`,
      "X-Requested-With": "XMLHttpRequest",
    },
  });

  if (!isJsonObject(response)) {
    loginResult = await loginToLk({
      forceLogin: true,
    });

    response = await lkRequest(loginResult.jar, {
      method: "GET",
      path: `/thermostat.json?tid=${tid}&_=${Date.now()}`,
      headers: {
        Accept: "*/*",
        Referer: `${LK_BASE_URL}/thermostat.htm?tid=${tid}`,
        "X-Requested-With": "XMLHttpRequest",
      },
    });
  }

  if (response.status >= 400) {
    throw new Error(
      `LK thermostat.json failed. HTTP ${
        response.status
      }: ${shortBody(response.data, 800)}`
    );
  }

  if (!isJsonObject(response)) {
    throw new Error(
      `LK thermostat.json was not JSON after relogin: ${shortBody(
        response.data,
        800
      )}`
    );
  }

  return {
    jar: loginResult.jar,
    raw: response.data,
  };
}

function normalizeMainJson(raw) {
  const names = raw.name || [];
  const sectionNames = raw.sect_name || [];
  const active = raw.active || [];
  const getRoomDeg = raw.get_room_deg || [];
  const setRoomDeg = raw.set_room_deg || [];
  const getFloorDeg = raw.get_floor_deg || [];
  const heatStatus = raw.heat_status || [];
  const zoneAlarms = raw.zone_alarms || [];
  const bypassStatus = raw.bypass_status || [];

  const zones = [];

  for (let index = 0; index < names.length; index++) {
    const isActive =
      String(active[index] || "0") === "1";

    if (!isActive) continue;

    zones.push({
      index,
      id: index + 1,
      receiverId: Math.floor(index / 8) + 1,
      receiverChannel: (index % 8) + 1,
      name: decodeHexLatin1(names[index]),
      currentTemperature: toCelsius(getRoomDeg[index]),
      floorTemperature: toCelsius(getFloorDeg[index]),
      setpoint: toCelsius(setRoomDeg[index]),
      heating:
        String(heatStatus[index] || "0") === "1",
      alarm:
        String(zoneAlarms[index] || "0") !== "0",
      bypass:
        String(bypassStatus[index] || "0") !== "0",
      raw: {
        name: names[index],
        active: active[index],
        get_room_deg: getRoomDeg[index],
        get_floor_deg: getFloorDeg[index],
        set_room_deg: setRoomDeg[index],
        heat_status: heatStatus[index],
        zone_alarms: zoneAlarms[index],
        bypass_status: bypassStatus[index],
      },
    });
  }

  const sections = sectionNames.map((name, index) => ({
    index,
    id: index + 1,
    name: decodeHexLatin1(name),
    softwareVersion: raw.sect_sw_version?.[index]
      ? Number(raw.sect_sw_version[index])
      : null,
    alarm: raw.sect_alarms?.[index]
      ? String(raw.sect_alarms[index]) !== "0"
      : false,
    actuatorAlarm: raw.sect_actuator_alarms?.[index]
      ? String(raw.sect_actuator_alarms[index]) !== "0"
      : false,
  }));

  return {
    system: {
      override: Number(raw.override || 0),
      wirelessId: raw.wireless_id ?? null,
      modbusStatus: raw.modbus_status ?? null,
    },
    sections,
    zones,
  };
}

function minutesToTime(minutes) {
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;

  return `${String(hours).padStart(2, "0")}:${String(
    remainder
  ).padStart(2, "0")}`;
}

function normalizeWeekProgram(rawWeekProgram = []) {
  const days = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
  ];

  return days.map((dayName, day) => {
    const events = [];

    for (let event = 0; event < 3; event++) {
      const index = day * 6 + event * 2;
      const start = Number(rawWeekProgram[index]);
      const end = Number(rawWeekProgram[index + 1]);

      if (
        Number.isFinite(start) &&
        Number.isFinite(end) &&
        start !== end
      ) {
        events.push({
          event: event + 1,
          startMinutes: start,
          endMinutes: end,
          start: minutesToTime(start),
          end: minutesToTime(end),
        });
      }
    }

    return {
      day,
      dayName,
      events,
    };
  });
}

function normalizeThermostatDetails(raw) {
  return {
    id: Number(raw.tid),
    name: decodeHexLatin1(raw.name),
    active: String(raw.active || "0") === "1",
    receiverId: raw.tid
      ? Math.floor((Number(raw.tid) - 1) / 8) + 1
      : null,
    receiverChannel: raw.ru_channel
      ? Number(raw.ru_channel)
      : null,
    roomUnitType: raw.ru_type
      ? Number(raw.ru_type)
      : null,
    battery:
      raw.battery !== undefined
        ? Number(raw.battery)
        : null,
    linkQuality:
      raw.link_quality !== undefined
        ? Number(raw.link_quality)
        : null,
    softwareVersion:
      raw.ru_sw_version !== undefined
        ? Number(raw.ru_sw_version)
        : null,
    currentTemperature: toCelsius(raw.get_room_deg),
    floorTemperature: toCelsius(raw.get_floor_deg),
    setpoint: toCelsius(raw.set_room_deg),
    comfortTemperature: toCelsius(raw.comfort_deg),
    economyTemperature: toCelsius(raw.economy_deg),
    holidayTemperature: toCelsius(raw.holiday_deg),
    setbackTemperature: toCelsius(raw.setback_deg),
    sensorModeMinTemperature: toCelsius(
      raw.sensor_mode_min_deg
    ),
    sensorModeMaxTemperature: toCelsius(
      raw.sensor_mode_max_deg
    ),
    restrictMinTemperature: toCelsius(
      raw.restrict_deg_min
    ),
    restrictMaxTemperature: toCelsius(
      raw.restrict_deg_max
    ),
    heating: String(raw.heat_status || "0") === "1",
    zoneAlarm:
      String(raw.zone_alarms || "0") !== "0",
    bypassStatus:
      String(raw.bypass_status || "0") !== "0",
    weekProgramEnabled:
      String(raw.week_program_enable || "0") === "1",
    weekProgramMode:
      raw.week_program_mode !== undefined
        ? Number(raw.week_program_mode)
        : null,
    weekSetpoint:
      raw.week_setpoint !== undefined
        ? Number(raw.week_setpoint)
        : null,
    operationMode:
      raw.operation_mode !== undefined
        ? Number(raw.operation_mode)
        : null,
    adaptiveEnabled:
      String(raw.adaptive_enable || "0") === "1",
    fireplaceHours:
      raw.fireplace_hours !== undefined
        ? Number(raw.fireplace_hours)
        : null,
    fireplaceLevelPercent:
      raw.fireplace_level !== undefined
        ? Number(raw.fireplace_level) / 100
        : null,
    backlightEnabled:
      String(raw.backlight_enable || "0") === "1",
    keylockEnabled:
      String(raw.keylock_enable || "0") === "1",
    sensorMode:
      raw.sensor_mode !== undefined
        ? Number(raw.sensor_mode)
        : null,
    bypassMode:
      raw.bypass_mode !== undefined
        ? Number(raw.bypass_mode)
        : null,
    actuatorZone: raw.actuator_zone || [],
    weekProgram: normalizeWeekProgram(
      raw.week_program || []
    ),
    raw,
  };
}

function extractBody(request) {
  return request.body &&
    typeof request.body === "object"
    ? request.body
    : {};
}

async function doUpdateSequence(paramsList) {
  let loginResult = await loginToLk();
  const updates = [];

  for (const params of paramsList) {
    let update;

    try {
      update = await lkUpdate(loginResult.jar, params);
    } catch (error) {
      loginResult = await loginToLk({
        forceLogin: true,
      });

      update = await lkUpdate(loginResult.jar, params);
    }

    updates.push(update);
  }

  return updates;
}

app.get("/health", async () => {
  return {
    ok: true,
    service: "vardagsarkivet-lk-integration",
    version: "0.4.1-lk-session-retry",
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
    userCookieConfigured: Boolean(LK_USER_COOKIE),
  };
});

app.get("/lk/test-login", async () => {
  const result = await loginToLk({
    forceLogin: true,
  });

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

async function buildZonesResponse() {
  const result = await getMainJson();
  const normalized = normalizeMainJson(result.raw);

  return {
    ok: true,
    ...normalized,
  };
}

app.get("/lk/zones", buildZonesResponse);
app.get("/integrations/lk/zones", buildZonesResponse);

app.get("/lk/thermostats", async () => {
  const result = await getMainJson();
  const normalized = normalizeMainJson(result.raw);

  return {
    ok: true,
    count: normalized.zones.length,
    thermostats: normalized.zones,
    sections: normalized.sections,
    system: normalized.system,
  };
});

app.get(
  "/lk/thermostats/:id",
  async (request, reply) => {
    const id = validateTid(request.params.id);
    const result = await getMainJson();
    const normalized = normalizeMainJson(result.raw);

    const thermostat = normalized.zones.find(
      (zone) => zone.id === id
    );

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
  }
);

app.get(
  "/lk/thermostats/:id/details",
  async (request) => {
    const result = await getThermostatJson(
      request.params.id
    );

    return {
      ok: true,
      thermostat: normalizeThermostatDetails(
        result.raw
      ),
    };
  }
);
app.post(
  "/lk/thermostats/:id/setpoint",
  async (request) => {
    const tid = validateTid(request.params.id);
    const body = extractBody(request);

    const temperature = toLkTemp(
      body.temperature ?? body.setpoint
    );

    const updates = await doUpdateSequence([
      {
        tid,
        set_room_deg: temperature,
      },
      {
        tid,
        operation_mode: 1,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/comfort",
  async (request) => {
    const tid = validateTid(request.params.id);
    const temperature = toLkTemp(
      extractBody(request).temperature
    );

    const updates = await doUpdateSequence([
      {
        tid,
        comfort_deg: temperature,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/economy",
  async (request) => {
    const tid = validateTid(request.params.id);
    const temperature = toLkTemp(
      extractBody(request).temperature
    );

    const updates = await doUpdateSequence([
      {
        tid,
        economy_deg: temperature,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/holiday-temperature",
  async (request) => {
    const tid = validateTid(request.params.id);
    const temperature = toLkTemp(
      extractBody(request).temperature
    );

    const updates = await doUpdateSequence([
      {
        tid,
        holiday_deg: temperature,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/setback-temperature",
  async (request) => {
    const tid = validateTid(request.params.id);
    const temperature = toLkTemp(
      extractBody(request).temperature
    );

    const updates = await doUpdateSequence([
      {
        tid,
        setback_deg: temperature,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/name",
  async (request) => {
    const tid = validateTid(request.params.id);
    const body = extractBody(request);

    const updates = await doUpdateSequence([
      {
        tid,
        setname: encodeHexLatin1(body.name),
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post("/lk/sections/:id/name", async (request) => {
  const cuid = Number(request.params.id);

  if (
    !Number.isInteger(cuid) ||
    cuid < 1 ||
    cuid > 8
  ) {
    throw new Error(
      "section id must be an integer between 1 and 8"
    );
  }

  const body = extractBody(request);

  const updates = await doUpdateSequence([
    {
      cuid,
      setname: encodeHexLatin1(body.name),
    },
  ]);

  return {
    ok: true,
    updates,
  };
});

app.post(
  "/lk/thermostats/:id/weekly-program-mode",
  async (request) => {
    const tid = validateTid(request.params.id);
    const enabled = toEnabled(
      extractBody(request).enabled
    );

    const updates =
      enabled === "1"
        ? await doUpdateSequence([
            {
              tid,
              week_program_enable: 1,
            },
            {
              tid,
              operation_mode: 0,
            },
            {
              tid,
              week_program_mode: 2,
            },
          ])
        : await doUpdateSequence([
            {
              tid,
              week_program_enable: 0,
            },
          ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/week-program",
  async (request) => {
    const tid = validateTid(request.params.id);
    const body = extractBody(request);
    const day = Number(body.day);

    if (
      !Number.isInteger(day) ||
      day < 0 ||
      day > 6
    ) {
      throw new Error(
        "day must be an integer 0-6 where 0=Monday and 6=Sunday"
      );
    }

    const events = Array.isArray(body.events)
      ? body.events.slice(0, 3)
      : [];

    const updatesToSend = [];

    for (let event = 0; event < 3; event++) {
      const index = day * 6 + event * 2;
      const item = events[event];

      if (item) {
        updatesToSend.push({
          tid,
          index,
          week_program: toMinutesFromMidnight(
            item.start
          ),
        });

        updatesToSend.push({
          tid,
          index: index + 1,
          week_program: toMinutesFromMidnight(
            item.end
          ),
        });
      } else {
        updatesToSend.push({
          tid,
          index,
          week_program: 720,
        });

        updatesToSend.push({
          tid,
          index: index + 1,
          week_program: 720,
        });
      }
    }

    const updates = await doUpdateSequence(
      updatesToSend
    );

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/adaptive",
  async (request) => {
    const tid = validateTid(request.params.id);
    const enabled = toEnabled(
      extractBody(request).enabled
    );

    const updates = await doUpdateSequence([
      {
        tid,
        adaptive_enable: enabled,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/fireplace",
  async (request) => {
    const tid = validateTid(request.params.id);
    const body = extractBody(request);
    const updatesToSend = [];

    if (body.enabled !== undefined) {
      const enabled = toEnabled(body.enabled);

      updatesToSend.push({
        tid,
        fireplace_hours:
          enabled === "1"
            ? Number(body.hours ?? 16)
            : 0,
      });
    } else if (body.hours !== undefined) {
      const hours = Number(body.hours);

      if (
        !Number.isFinite(hours) ||
        hours < 0 ||
        hours > 100
      ) {
        throw new Error(
          "fireplace hours must be 0-100"
        );
      }

      updatesToSend.push({
        tid,
        fireplace_hours: Math.round(hours),
      });
    }

    if (body.level !== undefined) {
      updatesToSend.push({
        tid,
        fireplace_level: normalizePercentToLk(
          body.level
        ),
      });
    }

    if (updatesToSend.length === 0) {
      throw new Error(
        "provide enabled, hours, or level"
      );
    }

    const updates = await doUpdateSequence(
      updatesToSend
    );

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/backlight",
  async (request) => {
    const tid = validateTid(request.params.id);
    const enabled = toEnabled(
      extractBody(request).enabled
    );

    const updates = await doUpdateSequence([
      {
        tid,
        backlight_enable: enabled,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/keylock",
  async (request) => {
    const tid = validateTid(request.params.id);
    const enabled = toEnabled(
      extractBody(request).enabled
    );

    const updates = await doUpdateSequence([
      {
        tid,
        keylock_enable: enabled,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/sensor-mode",
  async (request) => {
    const tid = validateTid(request.params.id);
    const body = extractBody(request);
    const updatesToSend = [];

    if (body.mode !== undefined) {
      const mode = Number(body.mode);

      if (![0, 1, 2, 3].includes(mode)) {
        throw new Error(
          "sensor mode must be 0, 1, 2, or 3"
        );
      }

      updatesToSend.push({
        tid,
        sensor_mode: mode,
      });
    }

    if (body.minTemperature !== undefined) {
      updatesToSend.push({
        tid,
        sensor_mode_min_deg: toLkTemp(
          body.minTemperature
        ),
      });
    }

    if (body.maxTemperature !== undefined) {
      updatesToSend.push({
        tid,
        sensor_mode_max_deg: toLkTemp(
          body.maxTemperature
        ),
      });
    }

    if (updatesToSend.length === 0) {
      throw new Error(
        "provide mode, minTemperature, or maxTemperature"
      );
    }

    const updates = await doUpdateSequence(
      updatesToSend
    );

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/bypass-mode",
  async (request) => {
    const tid = validateTid(request.params.id);
    const mode = Number(
      extractBody(request).mode
    );

    if (![0, 1, 2].includes(mode)) {
      throw new Error(
        "bypass mode must be 0, 1, or 2"
      );
    }

    const updates = await doUpdateSequence([
      {
        tid,
        bypass_mode: mode,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/restrict-range",
  async (request) => {
    const tid = validateTid(request.params.id);
    const body = extractBody(request);

    const minimum =
      body.enabled === false
        ? 700
        : toLkTemp(body.minTemperature ?? 7);

    const maximum =
      body.enabled === false
        ? 4000
        : toLkTemp(body.maxTemperature ?? 40);

    const updates = await doUpdateSequence([
      {
        tid,
        restrict_deg_min: minimum,
      },
      {
        tid,
        restrict_deg_max: maximum,
      },
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post(
  "/lk/thermostats/:id/update",
  async (request) => {
    const tid = validateTid(request.params.id);
    const body = extractBody(request);

    const allowedRawFields = new Set([
      "set_room_deg",
      "operation_mode",
      "comfort_deg",
      "economy_deg",
      "holiday_deg",
      "setback_deg",
      "week_program_enable",
      "week_program_mode",
      "adaptive_enable",
      "fireplace_hours",
      "fireplace_level",
      "backlight_enable",
      "keylock_enable",
      "sensor_mode",
      "sensor_mode_min_deg",
      "sensor_mode_max_deg",
      "bypass_mode",
      "restrict_deg_min",
      "restrict_deg_max",
    ]);

    const params = {
      tid,
    };

    for (const [key, value] of Object.entries(body)) {
      if (!allowedRawFields.has(key)) continue;

      params[key] = value;
    }

    if (Object.keys(params).length === 1) {
      throw new Error(
        "no allowed update fields supplied"
      );
    }

    const updates = await doUpdateSequence([
      params,
    ]);

    return {
      ok: true,
      updates,
    };
  }
);

app.post("/lk/system/holiday", async (request) => {
  const body = extractBody(request);
  const enabled = toEnabled(body.enabled);

  const updatesToSend = [
    {
      override_web: enabled === "1" ? 1 : 0,
    },
  ];

  if (
    enabled === "1" &&
    body.days !== undefined
  ) {
    const days = Number(body.days);

    if (
      !Number.isFinite(days) ||
      days < 1 ||
      days > 90
    ) {
      throw new Error(
        "holiday days must be 1-90"
      );
    }

    updatesToSend.push({
      holiday_counter: Math.round(days * 24),
    });
  }

  const updates = await doUpdateSequence(
    updatesToSend
  );

  return {
    ok: true,
    updates,
  };
});

app.post("/lk/system/setback", async (request) => {
  const enabled = toEnabled(
    extractBody(request).enabled
  );

  const updates = await doUpdateSequence([
    {
      override_web: enabled === "1" ? 2 : 0,
    },
  ]);

  return {
    ok: true,
    updates,
  };
});

app.setErrorHandler((error, request, reply) => {
  request.log.error(
    {
      error: error.message,
      stack: error.stack,
      method: request.method,
      url: request.url,
    },
    "LK integration request failed"
  );

  reply.code(500).send({
    ok: false,
    error: "internal_server_error",
    message: error.message,
  });
});

try {
  await app.listen({
    port: PORT,
    host: "0.0.0.0",
  });

  app.log.info(
    `LK integration service listening on port ${PORT}`
  );
} catch (error) {
  app.log.error(error);
  process.exit(1);
}

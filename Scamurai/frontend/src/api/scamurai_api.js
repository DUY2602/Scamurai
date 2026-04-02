import axios from "axios";

const runtimeApiBaseUrl = globalThis?.__APP_CONFIG__?.VITE_API_BASE_URL;
const API_BASE_URL =
  runtimeApiBaseUrl ??
  import.meta.env.VITE_API_BASE_URL ??
  (import.meta.env.DEV ? "http://localhost:8000" : "/api");
const SESSION_STORAGE_KEY = "scamurai_session_id";

function createSessionId() {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }

  return `scamurai-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function getSessionId() {
  if (typeof window === "undefined") {
    return "server-session";
  }

  const existing = window.localStorage.getItem(SESSION_STORAGE_KEY);
  if (existing) {
    return existing;
  }

  const nextSessionId = createSessionId();
  window.localStorage.setItem(SESSION_STORAGE_KEY, nextSessionId);
  return nextSessionId;
}

export const API = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
});

API.interceptors.request.use((config) => {
  const nextConfig = { ...config };
  nextConfig.headers = nextConfig.headers ?? {};
  nextConfig.headers["x-session-id"] = getSessionId();
  return nextConfig;
});

export function getApiErrorMessage(
  error,
  fallback = "Something went wrong. Please try again."
) {
  if (axios.isAxiosError(error)) {
    const responseData = error.response?.data;

    if (typeof responseData === "string") {
      return responseData;
    }

    if (typeof responseData?.detail === "string") {
      return responseData.detail;
    }

    if (typeof responseData?.message === "string") {
      return responseData.message;
    }

    if (!error.response) {
      return `Cannot connect to the backend at ${API_BASE_URL}. Make sure the server is running.`;
    }
  }

  return fallback;
}

export function analyzeUrl(url) {
  return API.post("/url", { url }).then((response) => response.data);
}

export function analyzeFile(formData) {
  return API.post("/file", formData).then((response) => response.data);
}

export function analyzeEmailFile(formData) {
  return API.post("/email/file", formData).then((response) => response.data);
}

export function analyzeEmailText(subject, body) {
  return API.post("/email/text", { subject, body }).then(
    (response) => response.data
  );
}

export function getDashboard() {
  return API.get("/dashboard/stats").then((response) => response.data);
}

export function getMetrics() {
  return API.get("/dashboard/model-metrics").then((response) => response.data);
}

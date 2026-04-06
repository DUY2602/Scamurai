import axios from "axios";

const runtimeApiBaseUrl = globalThis?.__APP_CONFIG__?.VITE_API_BASE_URL;
const API_BASE_URL =
  runtimeApiBaseUrl ??
  import.meta.env.VITE_API_BASE_URL ??
  (import.meta.env.DEV ? "http://127.0.0.1:8000" : "/api");
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
    const status = error.response?.status;

    if (typeof responseData === "string") {
      return responseData;
    }

    if (typeof responseData?.detail === "string") {
      return responseData.detail;
    }

    if (typeof responseData?.message === "string") {
      return responseData.message;
    }

    if (error.code === "ECONNABORTED") {
      return "The request took too long to finish. Please try again in a moment.";
    }

    if (!error.response) {
      return `Scamurai could not reach the API service at ${API_BASE_URL}. Please make sure the backend server is running and try again.`;
    }

    if (status === 400) {
      return "The request could not be processed. Please review your input and try again.";
    }

    if (status === 404) {
      return "The requested API endpoint was not found. Please check the current backend route configuration.";
    }

    if (status === 413) {
      return "The uploaded file is too large for the current API limits. Please choose a smaller file.";
    }

    if (status === 422) {
      return "The submitted data is incomplete or has an invalid format. Please check your input and try again.";
    }

    if (status === 429) {
      return "Too many requests were sent in a short time. Please wait a moment and try again.";
    }

    if (status >= 500) {
      return "The server encountered an internal error while processing the request. Please try again shortly.";
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

export function getDashboard(range = "week") {
  return API.get("/dashboard/stats", {
    params: { range },
  }).then((response) => response.data);
}

export function getMetrics() {
  return API.get("/dashboard/model-metrics").then((response) => response.data);
}

export function getDatasetInsights() {
  return API.get("/dashboard/dataset-insights").then((response) => response.data);
}

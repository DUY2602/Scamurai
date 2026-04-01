import axios from "axios";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export const API = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
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
  return API.get("/dashboard").then((response) => response.data);
}

export function getMetrics() {
  return API.get("/dashboard/model-metrics").then((response) => response.data);
}

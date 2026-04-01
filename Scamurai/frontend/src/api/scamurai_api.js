import axios from "axios";

export const API = axios.create({
  baseURL: "http://localhost:8001",
  timeout: 15000,
});

async function requestWithFallback(requests) {
  for (let index = 0; index < requests.length; index += 1) {
    try {
      const response = await API.request(requests[index]);
      return response.data;
    } catch (error) {
      const canRetry =
        axios.isAxiosError(error) &&
        error.response &&
        [404, 405].includes(error.response.status) &&
        index < requests.length - 1;

      if (canRetry) {
        continue;
      }

      throw error;
    }
  }

  return null;
}

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
      return "Cannot connect to the backend at http://localhost:8001. Make sure the server is running.";
    }
  }

  return fallback;
}

export function analyzeUrl(url) {
  return requestWithFallback([
    { method: "post", url: "/analyze-url/", data: { url } },
    { method: "post", url: "/url/", data: { url } },
  ]);
}

export function analyzeFile(formData) {
  return requestWithFallback([
    { method: "post", url: "/analyze-file/", data: formData },
    { method: "post", url: "/file/", data: formData },
  ]);
}

export function analyzeEmailFile(formData) {
  return requestWithFallback([
    { method: "post", url: "/analyze-email/file", data: formData },
    { method: "post", url: "/email/file", data: formData },
  ]);
}

export function analyzeEmailText(subject, body) {
  return requestWithFallback([
    { method: "post", url: "/analyze-email/text", data: { subject, body } },
    { method: "post", url: "/email/text", data: { subject, body } },
  ]);
}

export function getDashboard() {
  return requestWithFallback([
    { method: "get", url: "/dashboard/stats" },
    { method: "get", url: "/dashboard" },
  ]);
}

export function getMetrics() {
  return requestWithFallback([
    { method: "get", url: "/dashboard/model-metrics" },
    { method: "get", url: "/dashboard/metrics" },
  ]);
}

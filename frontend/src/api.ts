import axios from "axios";
import type { Scan } from "./types";
import { API_URL } from "./types";

const TOKEN_KEY = "socialshield_access_token";
const USER_KEY = "socialshield_user_info";

export interface AuthUser {
  username: string;
  role: string;
}

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getStoredUser(): AuthUser | null {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function setStoredSession(token: string, user: AuthUser): void {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearStoredSession(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

// Axios instance with JWT bearer token interceptor
export const apiClient = axios.create({
  baseURL: API_URL,
});

apiClient.interceptors.request.use((config) => {
  const token = getStoredToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export function getErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    return (
      error.response?.data?.detail ||
      error.message ||
      "The API request failed."
    );
  }
  return "An unexpected error occurred.";
}

export function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString("en-IN", {
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
}

export function getRiskClass(level: string): string {
  switch (level?.toLowerCase()) {
    case "critical":
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

export function getSeverityClass(severity?: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
    case "high":
      return "severity-high";
    case "medium":
      return "severity-medium";
    case "low":
      return "severity-low";
    default:
      return "severity-info";
  }
}

export async function loginUser(username: string, password: string): Promise<AuthUser> {
  const resp = await apiClient.post<{ access_token: string; username: string; role: string }>(
    "/api/auth/login",
    { username, password }
  );
  const user = { username: resp.data.username, role: resp.data.role };
  setStoredSession(resp.data.access_token, user);
  return user;
}

export async function fetchScans(): Promise<Scan[]> {
  const response = await apiClient.get<Scan[]>("/api/scans/");
  return Array.isArray(response.data) ? response.data : [];
}

export async function fetchScan(id: number): Promise<Scan> {
  const response = await apiClient.get<Scan>(`/api/scans/${id}`);
  return response.data;
}

export async function createScan(target: string): Promise<Scan> {
  const response = await apiClient.post<Scan>("/api/scans/", {
    target: target.trim(),
  });
  return response.data;
}

export async function deleteScan(id: number): Promise<void> {
  await apiClient.delete(`/api/scans/${id}`);
}

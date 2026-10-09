import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import FindingsPage from "./pages/FindingsPage";
import "./index.css";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Default: redirect root to login */}
        <Route path="/" element={<Navigate to="/login" replace />} />

        {/* Authentication */}
        <Route path="/login" element={<LoginPage />} />

        {/* Main dashboard */}
        <Route path="/dashboard" element={<DashboardPage />} />

        {/* Full findings report for a specific scan */}
        <Route path="/scans/:id" element={<FindingsPage />} />

        {/* Catch-all → dashboard */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
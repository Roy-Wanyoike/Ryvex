import type { NextConfig } from "next";

/**
 * Baseline browser security headers for the console (issue #42):
 * - X-Frame-Options: DENY           — the console must not be framed
 * - Referrer-Policy                 — never leak full URLs (tokens can sit in
 *                                      query strings) to cross-origin targets
 * - Permissions-Policy              — deny camera/microphone/geolocation outright
 */
const SECURITY_HEADERS = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  eslint: { ignoreDuringBuilds: false },
  async headers() {
    return [{ source: "/:path*", headers: SECURITY_HEADERS }];
  },
};

export default nextConfig;

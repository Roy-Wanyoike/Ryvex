/**
 * Control-plane version the console is built against — single source of
 * truth for the header version chip. Bump it alongside the daemon's
 * `Version` constant (`internal/api/server.go`) at release time so the
 * console and ryvexd never disagree again.
 */
export const RYVEX_VERSION = "v1.1.0";

/**
 * Token-storage hygiene tests for console/lib/api.ts (issue #77, issue #42).
 *
 * The bearer token is the one credential that must NEVER touch localStorage:
 * it lives in memory alone, or in sessionStorage when the operator explicitly
 * opts in ("remember in this browser"). Legacy consoles wrote it to
 * localStorage; hydrateApiFromStorage scrubs that copy on load.
 */
import { beforeEach, describe, expect, test } from "bun:test";
import {
  LS_API_BASE,
  LS_ENV,
  LS_ORG,
  LS_PROJECT,
  SS_TOKEN,
  configureApi,
  getApiBase,
  getApiMode,
  getApiToken,
  getEnv,
  getOrg,
  getProject,
  hydrateApiFromStorage,
  loadStoredConfig,
  storeConfig,
} from "@/lib/api";

beforeEach(() => {
  configureApi({ apiBase: "", token: "", org: "acme", project: "core", env: "prod" });
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe("storeConfig token persistence", () => {
  test("rememberToken opt-in writes sessionStorage only — never localStorage", () => {
    storeConfig("https://api.test/", "tok-1", { org: "o", project: "p", env: "e" }, { rememberToken: true });

    expect(window.sessionStorage.getItem(SS_TOKEN)).toBe("tok-1");
    // The credential must not exist anywhere in localStorage.
    expect(window.localStorage.getItem(SS_TOKEN)).toBeNull();
    // Non-secret settings are localStorage material.
    expect(window.localStorage.getItem(LS_API_BASE)).toBe("https://api.test");
    expect(window.localStorage.getItem(LS_ORG)).toBe("o");
    expect(window.localStorage.getItem(LS_PROJECT)).toBe("p");
    expect(window.localStorage.getItem(LS_ENV)).toBe("e");
    // And the runtime store reflects the new config.
    expect(getApiToken()).toBe("tok-1");
    expect(getApiBase()).toBe("https://api.test");
  });

  test("without opt-in the token stays in memory alone and any remembered copy is dropped", () => {
    window.sessionStorage.setItem(SS_TOKEN, "old-tok");
    storeConfig("https://api.test", "tok-2");

    expect(window.sessionStorage.getItem(SS_TOKEN)).toBeNull();
    expect(window.localStorage.getItem(SS_TOKEN)).toBeNull();
    expect(getApiToken()).toBe("tok-2"); // applied in-memory for this session only
  });

  test("a blank token is never persisted even with opt-in", () => {
    storeConfig("https://api.test", "   ", undefined, { rememberToken: true });
    expect(window.sessionStorage.getItem(SS_TOKEN)).toBeNull();
    expect(window.localStorage.getItem(SS_TOKEN)).toBeNull();
    expect(getApiToken()).toBe("");
  });
});

describe("hydrateApiFromStorage legacy-token scrub (issue #42)", () => {
  test("a legacy localStorage token is removed and never adopted", () => {
    window.localStorage.setItem(SS_TOKEN, "legacy-leak");

    hydrateApiFromStorage();

    expect(window.localStorage.getItem(SS_TOKEN)).toBeNull();
    expect(getApiToken()).toBe(""); // requests go out unauthenticated, not with the leaked token
  });

  test("the sessionStorage copy (opt-in) is adopted on hydrate", () => {
    window.sessionStorage.setItem(SS_TOKEN, "sess-tok");
    window.localStorage.setItem(LS_API_BASE, "https://stored.test");

    hydrateApiFromStorage();

    expect(getApiToken()).toBe("sess-tok");
    expect(getApiBase()).toBe("https://stored.test");
    expect(getApiMode()).toBe("live");
  });
});

describe("loadStoredConfig", () => {
  test("empty storages read as all-unset", () => {
    expect(loadStoredConfig()).toEqual({
      apiBase: "",
      token: "",
      org: "",
      project: "",
      env: "",
      hasBase: false,
      hasToken: false,
      hasOrg: false,
      hasProject: false,
      hasEnv: false,
    });
  });

  test("distinguishes 'stored but empty' from 'not set'", () => {
    window.localStorage.setItem(LS_API_BASE, ""); // explicitly cleared by the operator
    window.localStorage.setItem(LS_ORG, "acme");
    window.sessionStorage.setItem(SS_TOKEN, "sess-tok");

    const stored = loadStoredConfig();
    expect(stored.hasBase).toBe(true);
    expect(stored.apiBase).toBe("");
    expect(stored.hasOrg).toBe(true);
    expect(stored.org).toBe("acme");
    expect(stored.hasToken).toBe(true);
    expect(stored.token).toBe("sess-tok");
    expect(stored.hasProject).toBe(false);
    expect(stored.hasEnv).toBe(false);
  });

  test("hydrating an explicitly-empty base keeps demo mode", () => {
    window.localStorage.setItem(LS_API_BASE, "");
    hydrateApiFromStorage();
    expect(getApiBase()).toBe("");
    expect(getApiMode()).toBe("demo");
  });

  test("stored base/org/project/env win over the build-time defaults", () => {
    window.localStorage.setItem(LS_API_BASE, "https://from-settings.test");
    window.localStorage.setItem(LS_ORG, "globex");
    window.localStorage.setItem(LS_PROJECT, "infra");
    window.localStorage.setItem(LS_ENV, "staging");

    hydrateApiFromStorage();

    expect(getApiBase()).toBe("https://from-settings.test");
    expect(getApiMode()).toBe("live");
    expect(getOrg()).toBe("globex");
    expect(getProject()).toBe("infra");
    expect(getEnv()).toBe("staging");
  });
});

/**
 * Test preload (console/bunfig.toml [test] preload).
 *
 * Registers happy-dom globals so console modules can touch window,
 * localStorage, sessionStorage and document exactly like they do in the
 * browser. Must run before any test imports console/lib/api.ts.
 */
import { GlobalRegistrator } from "@happy-dom/global-registrator";

GlobalRegistrator.register();

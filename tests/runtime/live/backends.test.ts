import { describe, expect, it } from "vitest";

import { selectLiveProjects } from "./backends.ts";

const PACKAGED = {
  RUNFREE_E2E_ARTIFACT: "/repo/dist/runfree",
  RUNFREE_E2E_DOCKER_HOST: "unix:///var/run/docker.sock",
} as const;

describe("live project selection", () => {
  describe("packaged live lane (cli-e2e-live)", () => {
    it("is selected on Linux with TEST_RUNTIME_BACKEND unset", () => {
      const selection = selectLiveProjects({ ...PACKAGED }, [], "linux");
      expect(selection).toMatchObject({ backend: "docker-engine", cliE2e: true, cliE2eLive: true });
    });

    it("is selected on Linux with the Makefile default, docker-engine", () => {
      const selection = selectLiveProjects({ ...PACKAGED, TEST_RUNTIME_BACKEND: "docker-engine" }, [], "linux");
      expect(selection).toMatchObject({ backend: "docker-engine", cliE2eLive: true });
    });

    it("is selected on Linux with Docker Desktop named explicitly", () => {
      const selection = selectLiveProjects({ ...PACKAGED, TEST_RUNTIME_BACKEND: "docker-desktop" }, [], "linux");
      expect(selection).toMatchObject({ backend: "docker-desktop", cliE2eLive: true });
    });

    it("is selected on macOS with TEST_RUNTIME_BACKEND unset", () => {
      const selection = selectLiveProjects({ ...PACKAGED }, [], "darwin");
      expect(selection).toMatchObject({ backend: "docker-desktop", cliE2eLive: true });
    });

    it("is not selected for an unknown backend label", () => {
      const selection = selectLiveProjects({ ...PACKAGED, TEST_RUNTIME_BACKEND: "orbstack" }, [], "linux");
      expect(selection).toMatchObject({ cliE2e: true, cliE2eLive: false });
    });

    it("is not selected without a Docker host or without the artifact", () => {
      expect(selectLiveProjects({ RUNFREE_E2E_ARTIFACT: PACKAGED.RUNFREE_E2E_ARTIFACT }, [], "linux"))
        .toMatchObject({ cliE2e: true, cliE2eLive: false });
      expect(selectLiveProjects({ RUNFREE_E2E_DOCKER_HOST: PACKAGED.RUNFREE_E2E_DOCKER_HOST }, [], "linux"))
        .toMatchObject({ cliE2e: false, cliE2eLive: false });
    });
  });

  describe("runtime-live", () => {
    it("is not registered by a bare run with no backend named", () => {
      expect(selectLiveProjects({}, ["run"], "linux").runtimeLive).toBe(false);
      expect(selectLiveProjects({}, ["run"], "darwin").runtimeLive).toBe(false);
    });

    it("is registered for either named backend", () => {
      expect(selectLiveProjects({ TEST_RUNTIME_BACKEND: "docker-engine" }, [], "linux").runtimeLive).toBe(true);
      expect(selectLiveProjects({ TEST_RUNTIME_BACKEND: "docker-desktop" }, [], "linux").runtimeLive).toBe(true);
    });

    it("is registered by argv with the host default backend", () => {
      expect(selectLiveProjects({}, ["run", "--project", "runtime-live"], "linux"))
        .toMatchObject({ backend: "docker-engine", runtimeLive: true });
      expect(selectLiveProjects({}, ["run", "tests/runtime/live/request-shape.live.test.ts"], "darwin"))
        .toMatchObject({ backend: "docker-desktop", runtimeLive: true });
    });

    it("is not registered by a packaged e2e live filter", () => {
      expect(selectLiveProjects({}, ["run", "e2e/scenarios/packaged-runtime.live.test.ts"], "linux").runtimeLive)
        .toBe(false);
    });

    it("is not registered for an unknown named backend, even when argv selects it", () => {
      expect(selectLiveProjects({ TEST_RUNTIME_BACKEND: "orbstack" }, ["--project", "runtime-live"], "linux").runtimeLive)
        .toBe(false);
    });
  });
});

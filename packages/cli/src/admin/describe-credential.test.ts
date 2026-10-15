import { describe, expect, test } from "vitest";

import { describeCredential } from "./admin-core.ts";

describe("describeCredential", () => {
  test("shows basic with its username and the protocol scope, never a token", () => {
    expect(describeCredential({
      host: "gitlab.com",
      header: "Authorization",
      scheme: "basic",
      username: "oauth2",
      protocol: "git-http",
    })).toBe("gitlab.com -> Authorization (basic:oauth2, protocol=git-http)");
    expect(describeCredential({
      host: "gitlab.com",
      header: "Authorization",
      scheme: "bearer",
      pathPrefix: "/api/",
      protocol: "git-http",
    })).toBe("gitlab.com -> Authorization (bearer, path /api/, protocol=git-http)");
    expect(describeCredential({
      host: "github.com",
      header: "Authorization",
      scheme: "basic",
      username: "x-access-token",
      protocol: "git-lfs",
    })).toBe("github.com -> Authorization (basic:x-access-token, protocol=git-lfs)");
  });

  test("credentials without the new fields read as before", () => {
    expect(describeCredential({ host: "api.example.com", header: "Authorization", scheme: "bearer", pathPrefix: "/v1" }))
      .toBe("api.example.com -> Authorization (bearer, path /v1)");
    expect(describeCredential({ host: "api.example.com", header: "x-api-key", scheme: "raw" }))
      .toBe("api.example.com -> x-api-key (raw)");
  });
});

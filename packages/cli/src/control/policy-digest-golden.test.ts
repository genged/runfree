import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  desiredNetworkPolicyDigest,
  validateDesiredNetworkPolicy,
  type DesiredNetworkPolicyJson,
} from "@runfree/runtime-contracts/desired-network-policy";
import { validateNetworkPolicy } from "@runfree/runtime-contracts/network-policy";

import { SERVICES } from "../../../../scripts/services.ts";
import { desiredServiceEntry } from "../admin/service-policy.ts";
import { compileDesiredPolicies } from "./compiler.ts";

// Golden digests for desired v2 policies. A desired v2 file that a later
// release still accepts must keep the digest and the effective generation it
// had here: both are content addresses that approvals, the effective control
// manifest, and older proxies compare by value, so a change that re-encodes
// an unchanged v2 policy silently invalidates them. The literals are the
// values computed at the commit that added this file; update one only when the
// change to that policy's bytes is intended and its consequence is understood.
//
// The corpus lives in the CLI package rather than runtime-contracts because
// the service entries come from the CLI's `desiredServiceEntry` over the
// built-in registry. github and gitlab are left out: their definitions are
// expected to change revision for git-over-HTTPS credential mediation.
//
// Service entries embed `definitionDigest`, a hash of the registry definition,
// so an edit to a built-in service changes its golden here. That is intended:
// the edit changes the bytes every project that enabled the service stores.

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const EXCLUDED_SERVICES = new Set(["github", "gitlab"]);
const EMPTY_LOCAL: DesiredNetworkPolicyJson = { version: 2, hosts: [] };

type Golden = { digest: string; generation: string };

function goldenOf(policy: DesiredNetworkPolicyJson): Golden {
  const compiled = compileDesiredPolicies({ project: policy, local: EMPTY_LOCAL });
  return {
    digest: desiredNetworkPolicyDigest(policy),
    generation: validateNetworkPolicy(compiled.policy).generation,
  };
}

const templatePolicy = validateDesiredNetworkPolicy(
  JSON.parse(fs.readFileSync(path.join(repoRoot, "packages/cli/templates/network-policy.json"), "utf8")),
);

const mixedDirectTokenPolicy: DesiredNetworkPolicyJson = {
  version: 2,
  hosts: ["api.example.com", "files.example.com", "git.example.com", "raw.example.com"],
  requests: {
    "api.example.com": { methods: ["GET", "POST"], pathPrefixes: ["/v1"] },
    "git.example.com": { gitPush: "write", writeAction: "ask" },
    "raw.example.com": { methods: ["GET"] },
  },
  tokens: {
    "example-api": {
      description: "Example API token",
      credentials: [
        { host: "api.example.com", header: "Authorization", scheme: "bearer", pathPrefix: "/v1" },
        { host: "files.example.com", header: "X-Api-Key", scheme: "raw" },
      ],
    },
    "example-git": {
      description: "Example git token",
      allowAnonymous: true,
      credentials: [{ host: "git.example.com", header: "Authorization", scheme: "bearer" }],
    },
  },
  writeApproval: "deny",
};

const hostServicesPolicy: DesiredNetworkPolicyJson = {
  version: 2,
  hosts: ["api.example.com"],
  hostServices: {
    idb: { target: "host-loopback", port: 10882 },
    sim: { target: "host-loopback", port: 10883 },
  },
};

const DIRECT_GOLDENS: Array<[string, DesiredNetworkPolicyJson, Golden]> = [
  ["init template", templatePolicy, {
    digest: "sha256:a91346ef78000801615458103f3bd10fe85d2ab09819532a41e6d043a12869ec",
    generation: "sha256:87eeea0a70f3ba90abde9578bf81e8e205fb718fb275bb71e84bb34da0738fea",
  }],
  ["mixed direct tokens", mixedDirectTokenPolicy, {
    digest: "sha256:a5587a2d4ce8fc2b69fa32494941abbf5b5a36a1d1a672e2152cc4be7bbbf908",
    generation: "sha256:ee70cdfebb3332025bcd9035443a8ce355236cf14eb5a61e037cd7fdd20b5688",
  }],
  ["host services", hostServicesPolicy, {
    digest: "sha256:b35fa296a2956d9d6fe6023b1f8c58b1833f32e5af043cfaa5b600632081843c",
    generation: "sha256:4f3c14a7869c6e593041bb2e37fff79a90be285335a73bda97378029cd11857c",
  }],
];

const SERVICE_GOLDENS: Record<string, Golden> = {
  "agent-claude": {
    digest: "sha256:e86768f0f6b92723a272a36dd386ffc33e6ff3461036e4bab4bf66510a6ef457",
    generation: "sha256:fb1e78a7a6a99585174ae00f38063893a8526d4d125a7a42fd4774a0f06e5cae",
  },
  "agent-codex": {
    digest: "sha256:15955106146778312ac0fde53b80296a8ba45f090cc5dadb2898a7760396e0b3",
    generation: "sha256:4f004e9f8e5cb7272a88e180803cf462a001b3504871dd351e59fb607281c365",
  },
  "alpine-apk": {
    digest: "sha256:97764932569854acf692b89f29814ca9cd79c5094cbf995f5534c83f3b742822",
    generation: "sha256:47738b6edfc1510b2315a4d6fb71f3d1639432b1916056d8e1fde481148d915e",
  },
  "anthropic": {
    digest: "sha256:478dbf2369bcbd942d2599a158bf20798a4a917e97b4e3d0e9da99ec1fe25879",
    generation: "sha256:b3a475ba22aabb8b3ea816d2a12777f2d54805579f51fa40199eb351c04025c9",
  },
  "apple-ads": {
    digest: "sha256:3729591c258ae6d5b36a8d255aeab3a2e0c8b0e2fa85e38602e42e10b8b6ca3e",
    generation: "sha256:23d7d9b73816fb9eea5b183fe5f477790e13abe0829e21a47432898fb8263f67",
  },
  "appstore-connect": {
    digest: "sha256:afaa82ef99ef90264b779c22fb86c7429ff07e3620ed4e12515a503cac3bf56b",
    generation: "sha256:814fcb15a050b9420215b6e2903dd033745cc4424cab5d123c509f6e98675980",
  },
  "bitbucket": {
    digest: "sha256:b7308af63b32749e9c9846e48d89ed648c57ce24233e6eb3dc4dea24d80a5419",
    generation: "sha256:a87a45ce3341037a54dae15f945cd92994fb485788d72b1d7fb7f1c29d8bf0c0",
  },
  "conda": {
    digest: "sha256:34a90ff097bf8dcca038931ea956bc2419cb82f06c21f6e89a330b9ed337a64e",
    generation: "sha256:de4fe7eb5fa61173909fab12f58d7fc856503f0440912b02de838e2737a74898",
  },
  "dart": {
    digest: "sha256:6c147a12b40babd249e7d07204a65ccd57fdbcd948b0f0e87acc92cf3d13184e",
    generation: "sha256:191c00b7762f70f191a598ff517980795236257c27830c598cb40cdd04664c67",
  },
  "debian-apt": {
    digest: "sha256:640cee64db2483e3de688abacce87d153d56d22deb98996d54d5b1538bf417cf",
    generation: "sha256:ec212cfc160e9c96113fecbeb0a2f61172997dc5708634837180e7105b085b76",
  },
  "deepseek": {
    digest: "sha256:11ffa0f7e4bad1363d569804d3b364b49226719ba6d29afebdd832a7507d4590",
    generation: "sha256:924c123d7b6ffad76e7e621f503370cd7accb10bde4b57013f1bc1b8d0034ca5",
  },
  "docker-registry": {
    digest: "sha256:4844cb39f29457986aa868fe0ac17225eaa8ce7b0e0c27cb8d59210be95cec9a",
    generation: "sha256:6ede7300a57661e49611366a319fe1ab295b3cddfa2c5da4b8aafae387e47f96",
  },
  "dotnet": {
    digest: "sha256:d0d25cd226044cc29fd2ce2ff3c68adbab98eb0a4a0f0ffeaab2685da3f5a943",
    generation: "sha256:145512d78baebcf8434f1fd7d91e3049c2831f5e7e3b31d975f0dbe5dfc2cba2",
  },
  "elevenlabs": {
    digest: "sha256:6a1b809d7152062366a6631f9aae1d99ed0e1d208df8975d3176244a709c1781",
    generation: "sha256:ca68ff5cc8b14bc7e8d88cc8af1a63c52ba0dcab7f1675e844001699ba5e8902",
  },
  "gemini": {
    digest: "sha256:687abf058dc2eea4ad3d0bef914aaaf5b6a005929a83f016455f70eb4b42717b",
    generation: "sha256:bebac4b0b9b8cfc6a803f0d1a03085c0f170e74b89060d888a7c491ef3c95634",
  },
  "go": {
    digest: "sha256:77ff9115cb941cce0debb00cf2c769c5a4cfb31479559e960cc1354bd30a8377",
    generation: "sha256:6a6baad0db7062f72548be69a69c2ce0bda57fa405fb540ec6854c29425ce9e1",
  },
  "google-ads": {
    digest: "sha256:75f6cd06aa72303f6b2cf83ba1c086a4a63397dd500c700caec7a2f8d8cceedb",
    generation: "sha256:68ccb7998b6e2c874774b94465a1115ed7d0ff34e955937c84b8c3acef227583",
  },
  "groq": {
    digest: "sha256:9606e7d86ce9afe77edc58c0a870fceea9844d897788351a36868502c4b6ccb3",
    generation: "sha256:9e912135b2216a482c108c70f700d13874c89e5ea4bf2a835ee2348e7255c86a",
  },
  "homebrew": {
    digest: "sha256:5e304ab548cd44728c297eb96041d8ab37c6e48f4c01356c99ac27443eb82561",
    generation: "sha256:9cc38183b4a0fbb5f830e562e951094298a1d2bcaef918b69a04aa9c412eba63",
  },
  "java": {
    digest: "sha256:853b550db3fabb80a0e711c213880064e892b0456182edb5f26ea08b8dd2a1b3",
    generation: "sha256:d42de93f2ff0b0a7ff3f6c01c5e37f69a446185c22a6b4dd87c300c1381007c1",
  },
  "mistral": {
    digest: "sha256:9cd03ce6f0a340c41c209d207ecd399d8489d50d5e83c775b634f873ad7eb2a9",
    generation: "sha256:00fa382659e9a3674d056ff25b04eae4a31aea129614e45209dea83cde1bd825",
  },
  "node": {
    digest: "sha256:7df48a75b7b399b5075619ec57b6516ce57c213323376418d473140899816f84",
    generation: "sha256:f5d5ceb1041e67ce4f0b5dcce318b404af0a85ba7f93824298d9bf0b0c5893a4",
  },
  "openai": {
    digest: "sha256:a9f98ee4169f9ab96f9fa7f2c742e94ac9b07d0899a9a6e64da2f1083fce53ee",
    generation: "sha256:9c0ac43255e1668d10a3aa7c48f8ded9c5a06f460bddc2e0d98dd84d98e3e953",
  },
  "openrouter": {
    digest: "sha256:e3e6bb83f11273149e74db4cf927132507a5755bcc88c384980bf02dd1f955ba",
    generation: "sha256:e0505911bc3a9f19482f04101976c4e6d91a737a2528d5b18774f15f669030e9",
  },
  "perplexity": {
    digest: "sha256:14c43404f42eb64cfe6690a3bdee79d66d74e8c4f1034828b772592cae8d1b73",
    generation: "sha256:2620a5ce5c3fcd54ccf1ae99bb2dc70a75dba403ccab607ae843b95d02d92ccc",
  },
  "php": {
    digest: "sha256:5acd46b17ae12fa710fa1a2283bd11d61136119f239e62efe587b3f86758c9d7",
    generation: "sha256:e5497e6209953e65f3f4d0eecd563ba8a4a48eddb2a0b9f00595b929d9c9cb9d",
  },
  "python": {
    digest: "sha256:147d564a6f0f5fc6ca1cab9d1a6ff323cd657c1a972ec9316d14f1439562e115",
    generation: "sha256:c1a114776da2476ae0e37e969b2f336fe7cfccf4d9ae7302f5de022cd6f8fb05",
  },
  "ruby": {
    digest: "sha256:71b7dab5ccdfa6c98cb55c2179b22d7adfdc81b0dc9f254d9c4ef5a8672d3be4",
    generation: "sha256:2223fc4c44c16f7a18606306bda44b535107b6f90f3a87ef2d6d3dec1060ca3c",
  },
  "rust": {
    digest: "sha256:dd8d65d06e55060a84c6023fd23e29c2f58c8cacf93d14129f2196f9cd608a25",
    generation: "sha256:a9fb113f6142e0dff84ce9d746c8111832c846b4f8cdd6ed419d474dce16a5a7",
  },
  "terraform": {
    digest: "sha256:1ab548588988864404000f20dfb1c87cbe6691d881137235667a8a243b112308",
    generation: "sha256:c99d7825780b1d67ad35d6a051d519558dd73c4f7a16fa4b97036eb306777d9e",
  },
  "ubuntu-apt": {
    digest: "sha256:2ac33ae40df9cc25c95a1ceb6ee9115593f3e11e452f5de42e7b0386aa7b8230",
    generation: "sha256:7abc1fc69f14ad95ccf041f284682f24aed09c6490069ed083fc7ccd25e67855",
  },
  "xai": {
    digest: "sha256:f090210c79afb34fd99d77b100ab30db31c7498df72c2bc0ccf55a381109e9ae",
    generation: "sha256:6c06f3ac0aabf9daea196d870b8bcd4c93a0d6edd37c9112d2e4ac1e0f3a3a17",
  },
};

function servicePolicy(id: string): DesiredNetworkPolicyJson {
  const svc = SERVICES[id];
  if (!svc) throw new Error(`unknown built-in service ${id}`);
  return { version: 2, hosts: [], services: { [id]: desiredServiceEntry(svc) } };
}

describe("desired v2 policy digest goldens", () => {
  test.each(DIRECT_GOLDENS)("%s keeps its desired digest and effective generation", (_name, policy, golden) => {
    expect(goldenOf(policy)).toEqual(golden);
  });

  test("the golden set covers every built-in service except github and gitlab", () => {
    const expected = Object.keys(SERVICES).filter((id) => !EXCLUDED_SERVICES.has(id)).sort();
    expect(Object.keys(SERVICE_GOLDENS).sort()).toEqual(expected);
  });

  test.each(Object.entries(SERVICE_GOLDENS))("service %s keeps its desired digest and effective generation", (id, golden) => {
    expect(goldenOf(servicePolicy(id))).toEqual(golden);
  });
});

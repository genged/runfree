---
name: runfree
description: Read this when a network request fails with HTTP 403 "Runfree blocked this request", a proxy or CONNECT error, a TLS certificate error, or a connection error to an outside host, or when a token in the environment is rejected. It explains the Runfree sandbox, its proxy allowlist, placeholder tokens, and how to ask the human for access.
---

# Runfree sandbox

You run inside a Runfree sandbox. It is a container on a private network,
started by a human who uses the `runfree` command on their own machine (the
host). This skill is information only: it does not grant any access.

## Network

- All outbound traffic goes through the Runfree proxy. A firewall blocks
  direct connections, DNS lookups outside the proxy, and ports other than 443.
- The proxy allows HTTPS only, and only to hosts on the project allowlist.
- The allowlist names exact hostnames. There are no wildcards: allowing
  `api.example.com` does not allow `example.com` or `uploads.example.com`.
- A host can also have rules that allow only some methods or paths, or that
  hold writes for the human's approval.

## What a denial looks like

The proxy answers a denied request with HTTP status 403, a
`x-runfree-blocked: <reason>` header, and a plain-text body like this:

```text
Runfree blocked this request.

  host:   api.example.com
  reason: host is not in the project network allowlist

This block is enforced by the Runfree proxy outside the agent container.
If this host should be reachable, the person operating Runfree can run
on the host machine:

  runfree host add api.example.com

Policy reloads automatically; rerun the failed command afterwards.
```

Many clients never show this body. A client that checks certificates usually
fails with a TLS or certificate error for a denied host, and others show only
"403 Forbidden" or a failed connection. The proxy still records the denial,
and the human can see it on the host with `runfree doctor`. Other reasons use
the same format, and the body names the command that fixes it.

The proxy runs outside your container, so you cannot get past a denial.
Retrying, switching clients (curl, wget, Node, Python, git), unsetting the
proxy variables, using another port or protocol, or using an IP address does
not help. Do not try. Ask the human instead.

## Tokens

Token, key, and password variables in your environment hold placeholders, not
real values. When a request goes to an allowed host, the proxy replaces the
placeholder with the real token. So:

- A placeholder is expected. Do not report it as a missing or broken token.
- Use the variable as usual; do not ask the human to paste a real token.
- If a request is refused for a missing token, ask the human to set up the
  credential on the host.

## Asking the human for access

The `runfree` command does not exist in the sandbox. The human runs it on the
host. When you need a host that is denied, stop and tell the human:

1. the exact hostname, as the denial shows it (for example `api.example.com`);
2. why you need it;
3. the command to run on the host, copied from the denial body, for example:

```bash
runfree host add api.example.com
```

To see the current rules for a host, the human can run:

```bash
runfree host explain api.example.com
```

Ask for the narrowest access that does the job: one exact host, not a list of
guesses. Policy reloads automatically, so after the human runs the command,
rerun the failed command. If the denial names a different reason, such as a
blocked method or a write that needs approval, give the human the command the
denial body names, or suggest `runfree doctor` on the host.

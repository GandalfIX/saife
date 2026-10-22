---
name: sidecar-tngtech
description: Read the TNG Technology Consulting homepage from inside the sandbox through the host-side sidecar plugin. Use when you need tngtech.com content (title, text, links); direct HTTPS to that host is blocked by policy and will fail.
metadata:
  opencode/slash: "true"
---

# TNG homepage via the `tngtech` sidecar

You are running inside a sandbox. It has **no direct internet access**: a host-side *plugin*
(a "sidecar") owns the network on your behalf and is reachable only at a reserved hostname under
`.sandbox.invalid`. This skill is for the `tngtech` plugin, which serves one page.

## Call it

```powershell
curl.exe -s http://tngtech.sandbox.invalid/
```

- Plain **http**, never `https`.
- Only `GET /` is supported in this build. Other methods answer `501 facade_method_unsupported`.

To keep output small, filter inside the sandbox:

```powershell
curl.exe -s http://tngtech.sandbox.invalid/ | findstr /i "<title>"
```

## What comes back

The HTML of `https://www.tngtech.com/` — byte-identical to what the host would receive — with
status 200 and `Content-Type: text/html`.

## Do not

- Do **not** fetch `https://www.tngtech.com/` (or `http://`) yourself. Policy denies it: the proxy
  answers `CONNECT 403`. That is not a missing grant and retrying will not help — this sidecar exists
  so that the real host is never reachable from inside the sandbox.
- Do **not** use `https://tngtech.sandbox.invalid/`. The proxy refuses `CONNECT` to that name with
  `facade_requires_http`; the facade is plain HTTP only.

## If it fails

| Response | Meaning | What to do |
|---|---|---|
| `404 facade_unknown_mount` | this session was started without `--plugin tngtech` | tell the operator to restart the session with `--plugin tngtech` |
| `403 facade_requires_http` | you used `https` or tried `CONNECT` | use `http://` |
| `401` | you reached the sidecar directly, bypassing the proxy | call `http://tngtech.sandbox.invalid/` instead |
| `502` | the sidecar could not reach the upstream | report the failure; do not loop-retry |
| `501` | method other than GET | only `GET /` exists |

## Other sidecars

Only the plugins the session was started with exist. Each is reachable at
`http://<plugin-name>.sandbox.invalid/`, and each has its own skill describing what it serves.
If you need something that no skill mentions, ask the operator which plugins the session was
started with rather than guessing hostnames.

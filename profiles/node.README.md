# `node` profile

For Node.js work: `node`, `npm`, `npx`, and any CLI installed through npm
(the agent CLIs — opencode, typescript, eslint — are all Node programs).

## Verified

`npm install` + `require` inside the sandbox; `npx 11.6.2`, `node v24.13.0`
resolvable by bare name.

## Grants, and why each is what it is

| grant | why |
|---|---|
| `allow: $CWD` | the workspace. Seeded writable by `filesystem_policy` anyway; listing it documents intent. |
| `allow: $LOCALAPPDATA/npm-cache` | npm writes downloads and metadata here on every install. Read-write because the package cache **is** the install path's twin. |
| `allow: $APPDATA/npm` | npm's global prefix for user-scope installs. |
| `read_only: $LOCALAPPDATA/nvm`, `C:/nvm4w` | the Node runtimes themselves. **RX, never writable**: a workload that can replace the interpreter it runs from is the same hazard the launcher rule refuses. Read+execute is exactly what running code needs. |
| `read_only: $USERPROFILE/.npmrc` | registry tokens and config. npm needs to read it; nothing in a session needs to rewrite your registry settings. |
| `deny: $HOME/.ssh`, `$HOME/.aws` | belt and braces: cloud/SSH credentials must stay out of every profile, allow-list or not. |

## Network

`registry.npmjs.org`, `registry.npmjs.com` (redirect target), `nodejs.org`
(nvm installs). Everything else is a per-host prompt decision.

## Known constraints

- npm/npx/nvm are **batch shims**: call them as `cmd /c "npm …"`. The launcher
  does not apply `PATHEXT`, so a bare name only works for real `.exe` images.
- If your Node lives somewhere else (a venv-style install dir on `PATH`), add
  **that directory read-only**. An unreadable `PATH` directory is reported as
  *file not found* (0x80070002), not as access denied — see the FAQ.

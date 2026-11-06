# Nizlo security indicators

First-party, machine-readable Windows and macOS artifacts plus expected network behavior for identifying an authorized Nizlo RMM deployment.

- [Human-readable reference](https://nizlo.com/guides/nizlo-rmm-security-indicators)
- [Public dataset page](https://izikipizi.github.io/nizlo-security-indicators/)
- [JSON download](https://izikipizi.github.io/nizlo-security-indicators/indicators.json)
- [CSV download](https://izikipizi.github.io/nizlo-security-indicators/indicators.csv)
- [JSON Schema](https://izikipizi.github.io/nizlo-security-indicators/indicators.schema.json)
- [LLM-readable summary](https://izikipizi.github.io/nizlo-security-indicators/llms.txt)

## Important context

Nizlo is legitimate remote monitoring and management software. Finding one of these artifacts is not proof of compromise. Confirm tenant ownership, endpoint authorization, installer provenance, executable signature or hash, service configuration, technician identity, audit history, and the action performed before deciding whether activity is expected or suspicious.

This dataset intentionally does not publish unstable file hashes, unverified certificate attributes, shared-host indicators, or abuse claims. The remote bridge filename is documented, but its path can vary.

## Included indicators

The dataset covers:

- `Nizlo.Agent.exe`
- `Nizlo.Agent.Updater.exe`
- `Nizlo.RemoteBridge.exe`
- `C:\Program Files\Nizlo\Agent\`
- `C:\ProgramData\Nizlo\Agent\`
- `Nizlo RMM Agent`
- Nizlo agent and URL-protocol registry locations
- `nizlo:` and `nizlo-remote:` protocol handlers
- `app.nizlo.com` over outbound TCP 443 using HTTPS or authenticated WSS; no inbound firewall port is required
- `/Library/PrivilegedHelperTools/com.nizlo.agent/Nizlo.Agent.Mac`
- `/Applications/NizloRemote.app/Contents/MacOS/NizloRemote`
- `com.nizlo.NizloRemote_service` and `com.nizlo.NizloRemote_server` launchd labels

## Validate locally

The validator uses only Node.js built-ins.

```sh
npm test
```

It verifies the schema, exact documented values, unique rows, CSV/JSON parity, public-page links, disclosure language, and the byte-for-byte copies served by GitHub Pages.

## Versioning and corrections

Releases use semantic versioning. A changed artifact set increments the minor version; corrections that do not change the artifact set increment the patch version. Open an issue with reproducible first-party evidence for a proposed correction. Do not submit secrets, tenant identifiers, customer data, access tokens, or private incident details.

## Ownership and license

Nizlo maintains this repository. That relationship is disclosed so defenders can evaluate the provenance and scope of the data. The files are licensed under the MIT License to permit reuse in authorized defensive workflows.

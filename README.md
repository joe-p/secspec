# SecSpec

SecSpec is a CLI tool that helps audit and write security-related settings across various services. It currently supports npm and GitHub.

## The Sec Spec

The desired settings are specified in a JSON file, `secspec.json` by default. Where possible, the shape of the settings in the sec spec will align with shape of the same action if directly using the service's API.

## Docs

### CLI

`secspec audit` - ensures settings match the `secspec.json`, but does not write anything. This will return ALL mismatches and return a non-zero exit code for one or more mismatches.
`secspec diff` - returns any settings specified in the `secspec.json` that do not match their expected value. This will always return a zero status unless there is an internal error.
`secspec write` - write the settings defined in `secspec.json` to the respective packages/repositories. **Not implemented yet.**

Both read-only commands accept `--json` for a machine-readable report and `--spec <path>` to override the spec location.

### Authentication

GitHub requests use a token from `GH_TOKEN`/`GITHUB_TOKEN` (or `--github-token`); npm requests use `NPM_TOKEN` (or `--npm-token`). Endpoints can be overridden with `GITHUB_API_URL`/`--github-api-url` and `NPM_REGISTRY`/`--npm-registry`.

npm's trusted-publisher endpoints are gated behind 2FA. When the registry asks for a one-time password and none was supplied, `secspec` prompts for a code on the terminal (`/dev/tty`, so it never consumes stdin or pollutes a `--json` report) and retries. To run unattended, set `NPM_OTP`/`--npm-otp`, or pass `--non-interactive` to make a 2FA challenge fail with an error instead of prompting. Prompting is also skipped automatically when no terminal is available.

### Building

```
go build -o secspec .
go test ./...
```

### Sec Specs

#### GitHub Specs

`include_repos` - Array of strings that specify the repos these settings should apply to. Orgs must be fully specified, but repository names can contain the `*` wildcard.
`rulesets` - Array of objects matching the body parameters of GitHub's `POST /repos/{owner}/{repo}/rulesets` ([API docs](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10#create-a-repository-ruleset)).

#### NPM Specs

`include_packages` - Array of strings that specify the packages these settings should apply to. Scope must be fully specified, but package names can contain the `*` wildcard.
`trust` - Array of objects matching the body parameters of NPM's `POST /-/package/{package}/trust` ([API docs](https://api-docs.npmjs.com/#tag/Trust/operation/configureTrustedPublisher)). If `claims.repository` is omitted, the repository is read from the value specified in the `repository.url` field of the `package.json`.

# SecSpec

SecSpec is a CLI tool that helps audit and write security-related settings across various services. It currently supports npm and GitHub.

## The Sec Spec

The desired settings are specified in a JSON file, `secspec.json` by default. Where possible, the shape of the settings in the sec spec will align with shape of the same action if directly using the service's API.

## Docs

### CLI

`secspec audit` - ensures settings match the `secspec.json`, but does not write anything. This will return ALL mismatches and return a non-zero exit code for one or more mismatches.
`secspec diff` - returns any settings specified in the `secspec.json` that do not match their expected value. This will always return a zero status unless there is an internal error.
`secspec write` - creates settings that are missing and updates those that do not match the `secspec.json`. It never deletes settings that are absent from the spec.

Both read-only commands accept `--json` for a machine-readable report and `--spec <path>` to override the spec location; `write` accepts the same flags.

### Write behaviour

`write` matches settings by identity — GitHub rulesets by `name`, npm trust configurations by `type` plus claims. Missing ones are created and mismatched ones are replaced with the spec's fields; extra live settings are left untouched. GitHub `PUT` replaces the ruleset with the fields in the spec, so unspecified fields revert to their defaults. An existing ruleset defined at the organization or enterprise level is reported as an error rather than modified. For npm, the API requires `claims.repository`, so it is filled from the package's `package.json` when omitted, and the write fails if it cannot be resolved. npm trust writes are 2FA-gated and use the same interactive prompt described below.

### Authentication

GitHub requests use a token from `GH_TOKEN`/`GITHUB_TOKEN` (or `--github-token`). If none is set, `secspec` falls back to `gh auth token` when the [GitHub CLI](https://cli.github.com/) is installed and authenticated for the relevant host, so an existing `gh auth login` can be used without exporting a token. npm requests use `NPM_TOKEN` (or `--npm-token`). Endpoints can be overridden with `GITHUB_API_URL`/`--github-api-url` and `NPM_REGISTRY`/`--npm-registry`.

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

Because rulesets target branches by default, GitHub requires `conditions.ref_name` and rejects a request without it with `Branch conditions missing`. Use `~DEFAULT_BRANCH` to match whatever the repository's default branch is, or list explicit refs such as `refs/heads/main`:

```json
"conditions": {
  "ref_name": {
    "include": ["~DEFAULT_BRANCH"],
    "exclude": []
  }
}
```

#### NPM Specs

`include_packages` - Array of strings that specify the packages these settings should apply to. Scope must be fully specified, but package names can contain the `*` wildcard.
`trust` - Array of objects matching the body parameters of NPM's `POST /-/package/{package}/trust` ([API docs](https://api-docs.npmjs.com/#tag/Trust/operation/configureTrustedPublisher)). If `claims.repository` is omitted, the repository is read from the value specified in the `repository.url` field of the `package.json`.

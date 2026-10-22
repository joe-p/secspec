# SecSpec

SecSpec is a CLI tool that helps audit and write security-related settings across various services. It currently supports npm and GitHub.

## The Sec Spec

The desired settings are specified in a JSON file, `secspec.json` by default. Where possible, the shape of the settings in the sec spec will align with shape of the same action if directly using the service's API.

## Docs

### CLI

`secspec audit` - ensures settings match the `secspec.json`, but does not write anything. This will return ALL mismatches and return a non-zero exit code for one or more mismatches.
`secspec write` - write the settings defined in `secspec.json` to the respective packages/repositories.
`secspec diff` - returns any settings specified in the `secspec.json` that do not match their expected value. This will always return a zero status unless there is an internal error.

### Sec Specs

#### GitHub Specs

`include_repos` - Array of strings that specify the repos these settings should apply to. Orgs must be fully specified, but repository names can contain the `*` wildcard.
`rulesets` - Object matching the body parameters of GitHub's `POST /repos/{owner}/{repo}/rulesets` ([API docs](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10#create-a-repository-ruleset)).

#### NPM Specs

`include_repos` - Array of strings that specify the repos these settings should apply to. Scope must be fully specified, but package names can contain the `*` wildcard.
`trust` - Object matching the body parameters of NPM's `POST /-/package/{package}/trust` ([API docs](https://api-docs.npmjs.com/#tag/Trust/operation/configureTrustedPublisher)). If `claims.repository` is omitted, the repository is read from the value specified in the `repository.url` field of the `package.json`.

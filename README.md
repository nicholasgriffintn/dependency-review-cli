# Dependency Review CLI

The aim of this repo is to provide a standalone CLI tool that largely does a similar job to the [dependency-review-action](https://github.com/actions/dependency-review-action) but can be run locally or in any CI/CD environment through a CLI.

It also aims to expand some of the functionality where it makes sense to do so.

Currently, it is capable of:

- Retrieving your dependency review results from the [GitHub Dependency Graph API](https://docs.github.com/en/rest/dependency-graph/dependency-review?apiVersion=2022-11-28).
- Checking the dependencies returned to ensure they do not contain any vulnerabilities, invalid licenses, or restricted packages.
- Erroring at configurable levels of severity (low, moderate, high, critical).
- Erroring if there are any licenses that are not compatible with the licenses you have allowed.
- Retrieving the OpenSSF Scorecard for the dependencies.
- Optionally commenting on a GitHub PR with the results.

## Installation

You can use the following commands to install the CLI (pnpm is not required, just swap that out for your package manager of choice):

```bash
# Install globally
pnpm add -g dependency-review-cli

# Install locally
pnpm add -D dependency-review-cli
```

### Run without installation

```bash
# PNPX
pnpx dependency-review-cli <owner> <repo> <base-ref> <head-ref>

# NPM
npx dependency-review-cli <owner> <repo> <base-ref> <head-ref>
```

## Usage

### Set your GitHub token

The tool requires a GitHub token to access the Dependency Graph API. Set the `GITHUB_TOKEN` environment variable:

```bash
export GITHUB_TOKEN=your_github_token
```

The token needs:
- "Contents" repository permissions (read)

You can find out more about the permissions required for the token [here](https://docs.github.com/en/rest/dependency-graph/dependency-review?apiVersion=2022-11-28#get-a-diff-of-the-dependencies-between-commits).

For PR commenting, the token also needs:
- "Pull requests" repository permissions (write)

### Basic Usage

```bash
# Compare dependency changes between two commits
dependency-review github dependency-review-cli abc123 def456

# Compare between branches
dependency-review myorg myrepo main feature-branch

# Compare with specific commit and branch
dependency-review myorg myrepo v1.0.0 HEAD
```

Here are some more examples that you can run:

#### Check PR Changes

```bash
# Check changes in a pull request
pnpx dependency-review-cli nicholasgriffintn dependency-review-cli main this-pr-should-fail

# Only check critical and high severity vulnerabilities
pnpx dependency-review-cli --fail-on-severity high nicholasgriffintn dependency-review-cli main this-pr-should-fail

# Get clean JSON output for further processing
pnpx dependency-review-cli --quiet --output json nicholasgriffintn dependency-review-cli main this-pr-should-fail > review.json
```

#### License Checking

```bash
# Allow only specific licenses
pnpx dependency-review-cli --config license-config.yml nicholasgriffintn dependency-review-cli main this-pr-should-fail

# Disable license checking entirely
pnpx dependency-review-cli --no-license-check nicholasgriffintn dependency-review-cli main this-pr-should-fail
```

### CLI Options

Run the command with the `--help` flag to see all the available options:

```bash
dependency-review --help
```

### Output Formats

```bash
# Summary - default
dependency-review owner repo main HEAD

# Markdown
dependency-review --output markdown owner repo main HEAD

# Table
dependency-review --output table owner repo main HEAD

# JSON
dependency-review --output json owner repo main HEAD
```

## Configuration

### Using a

Create a `.dependency-review.yml` file:

```yaml
# Vulnerability settings
fail-on-severity: moderate
fail-on-scopes:
  - runtime
  - development

# License settings
licenses:
  allow:
    - MIT
    - Apache-2.0
    - BSD-3-Clause

# Package exclusions from license checking
license-check-exclusions:
  - pkg:npm/trusted-package-with-restricted-license

# Package restrictions
packages:
  deny:
    - pkg:npm/lodash@4.17.20

# Group restrictions
groups:
  deny:
    - pkg:npm/@bad-namespace/

# Advisory exceptions
ghsas:
  allow:
    - GHSA-1234-5678-9012

# Check toggles
license-check: true
vulnerability-check: true
warn-only: false
```

Use the config file:

```bash
dependency-review --config .dependency-review.yml owner repo main HEAD
```

### Environment Variables

- `GITHUB_TOKEN` - GitHub personal access token (required)
- `GITHUB_API_URL` - An optional GitHub API URL (for GitHub Enterprise)

### CI/CD Integration

#### GitHub Actions

```yaml
- name: Dependency Review
  run: |
    pnpx dependency-review-cli \
      ${{ github.repository_owner }} \
      ${{ github.event.repository.name }} \
      ${{ github.event.pull_request.base.sha }} \
      ${{ github.event.pull_request.head.sha }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### GitLab CI

```yaml
dependency-review:
  script:
    - pnpx dependency-review-cli owner repo $CI_MERGE_REQUEST_TARGET_BRANCH_SHA $CI_COMMIT_SHA
  variables:
    GITHUB_TOKEN: $GITHUB_TOKEN
```

## Error Codes

- `0` - No issues found
- `1` - Issues found (vulnerabilities, license violations, denied packages)
- `2` - Configuration or authentication error
- `3` - API error (repository not found, network issues, etc.)

## Troubleshooting

### Common Issues

1. **"Repository not found"**
   - Check repository name and owner
   - Ensure token has correct permissions
   - Verify repository visibility

2. **"Dependency graph not enabled"**
   - Enable dependency graph in repository settings
   - For private repos, ensure GitHub Advanced Security is enabled

3. **"No dependency changes found"**
   - Verify the base and head refs exist
   - Check that there are actual dependency changes between refs

### Debug Mode

Set `DEBUG=dependency-review` for verbose logging:

```bash
DEBUG=dependency-review dependency-review owner repo main HEAD
```
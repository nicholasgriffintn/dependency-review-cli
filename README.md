# Dependency Review CLI

A standalone CLI tool for reviewing dependency changes and vulnerabilities using the GitHub API. This tool provides the similar functionality to the [dependency-review-action](https://github.com/actions/dependency-review-action) but can be run locally or in any CI/CD environment through a CLI.

## Features

- 🔍 **Vulnerability Detection**: Retrieves known security vulnerabilities in dependencies.
- ⚖️ **License Compliance**: Check license compatibility and restrictions (Please note that by default, we have set a list of common copyleft licenses you can override this in the config file).
- 🚫 **Package Restrictions**: Block specific packages or namespaces.
- 📊 **Multiple Output Formats**: JSON, table, or summary formats,
- 🎯 **Flexible Configuration**: Configure via CLI options or config files,
- 🔍 **OpenSSF Scorecard**: Retrieves the OpenSSF Scorecard for the dependencies,
- 🚀 **GitHub Integration**: Uses the same GitHub Dependency Graph API as the official action, and supports PR commenting.

## Installation

### Global Installation

```bash
pnpm add -g dependency-review-cli
```

### Project Installation

```bash
pnpm add -D dependency-review-cli
```

### Run with pnpx

```bash
pnpx dependency-review-cli <owner> <repo> <base-ref> <head-ref>
```

## Authentication

The tool requires a GitHub token to access the Dependency Graph API. Set the `GITHUB_TOKEN` environment variable:

```bash
export GITHUB_TOKEN=your_github_token
```

The token needs:
- "Contents" repository permissions (read)

You can find out more about the permissions required for the token [here](https://docs.github.com/en/rest/dependency-graph/dependency-review?apiVersion=2022-11-28#get-a-diff-of-the-dependencies-between-commits).

## Usage

### Basic Usage

```bash
# Compare dependency changes between two commits
dependency-review github dependency-review-cli abc123 def456

# Compare between branches
dependency-review myorg myrepo main feature-branch

# Compare with specific commit and branch
dependency-review myorg myrepo v1.0.0 HEAD
```

## Examples

### Check PR Changes

```bash
# Check changes in a pull request
dependency-review myorg myrepo main pr-branch

# Only check critical and high severity vulnerabilities
dependency-review --fail-on-severity high myorg myrepo main pr-branch

# Get JSON output for further processing
dependency-review --output json myorg myrepo main pr-branch > review.json
```

### License Checking

```bash
# Allow only specific licenses
dependency-review --config license-config.yml owner repo main HEAD

# Disable license checking entirely
dependency-review --no-license-check owner repo main HEAD
```

### CLI Options

Run the command with the `--help` flag to see all the available options:

```bash
dependency-review --help
```

### Output Formats

#### Summary (default)
Human-readable summary with color-coded results:

```bash
dependency-review owner repo main HEAD
```

#### Table
Structured table format:

```bash
dependency-review --output table owner repo main HEAD
```

#### JSON
Machine-readable JSON for integration:

```bash
dependency-review --output json owner repo main HEAD
```

## Configuration

### Configuration File

Create a `.dependency-review.yml` file:

```yaml
# Vulnerability settings
fail-on-severity: moderate
fail-on-scopes:
  - runtime
  - development

# License settings  
allow-licenses:
  - MIT
  - Apache-2.0
  - BSD-3-Clause
  
# Package restrictions
deny-packages:
  - pkg:npm/lodash@4.17.20
deny-groups:
  - pkg:npm/@bad-namespace/

# Advisory exceptions
allow-ghsas:
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
- `GITHUB_API_URL` - GitHub API URL (for GitHub Enterprise)

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
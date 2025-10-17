# Release Workflow Testing Guide

This document explains how to test and enable the release workflow.

## Current Status: TESTING MODE

The release workflow is in **testing mode** with manual triggers only.
Tag-based releases are **disabled** until testing is complete.

## How to Test

### 1. Manual Test Run

1. Go to GitHub: **Actions** → **Release** → **Run workflow**
2. Fill in:
   - **Branch**: `master`
   - **Release tag**: `v0.0.1-test`
   - **Create as draft**: `true`
3. Click **Run workflow**

### 2. What Gets Tested

- ✅ All 8 platform builds (32 binaries total)
- ✅ Checksum generation (SHA256SUMS.txt)
- ✅ Artifact naming with version
- ✅ Draft release creation
- ✅ All files uploaded correctly

### 3. Verify Results

After the workflow completes (~10-15 minutes):

1. Go to **Releases** → Find draft release `v0.0.1-test`
2. Check that all files are present:
   - 32 binaries (4 programs × 8 platforms)
   - 1 SHA256SUMS.txt file
   - 1 README.txt file
3. Download a binary and verify:
   ```bash
   # Download binary + SHA256SUMS.txt
   sha256sum -c SHA256SUMS.txt
   ```
4. Test the binary works:
   ```bash
   chmod +x pocx_miner-v0.0.1-test-x86_64-unknown-linux-gnu
   ./pocx_miner-v0.0.1-test-x86_64-unknown-linux-gnu --version
   ```

### 4. Clean Up Test Release

After verifying everything works:

1. Delete the draft release (GitHub UI)
2. Optional: Delete the test tag if created:
   ```bash
   git push --delete origin v0.0.1-test
   git tag -d v0.0.1-test
   ```

## Enable Production Releases

Once testing is successful:

### Edit `.github/workflows/release.yml`

**Uncomment lines 4-6**:
```yaml
on:
  push:
    tags:
      - 'v[0-9]+.[0-9]+.[0-9]+*'  # v1.0.0, v1.0.0-beta, v1.0.0-rc1, etc.
```

**Commit and push**:
```bash
git add .github/workflows/release.yml
git commit -m "Enable tag-based releases"
git push origin master
```

## Create First Release

### Option 1: Beta Release (Recommended First)

```bash
# Update all Cargo.toml versions to 1.0.0-beta
find . -name Cargo.toml -exec sed -i 's/^version = "1.0.0"/version = "1.0.0-beta"/' {} \;

git add -A
git commit -m "Bump version to 1.0.0-beta"
git tag v1.0.0-beta
git push origin master
git push origin v1.0.0-beta
```

### Option 2: Release Candidate

```bash
# Update versions to 1.0.0-rc1
git tag v1.0.0-rc1
git push origin v1.0.0-rc1
```

### Option 3: Stable Release

```bash
# Update versions to 1.0.0
git tag v1.0.0
git push origin v1.0.0
```

## Versioning Strategy

Use semantic versioning:

- `v1.0.0-beta` - Pre-release for testing
- `v1.0.0-rc1` - Release candidate
- `v1.0.0` - Stable release
- `v1.1.0` - Minor release (new features)
- `v1.1.1` - Patch release (bug fixes)
- `v2.0.0` - Major release (breaking changes)

## Manual Binary Uploads

You can always add binaries manually to any release:

### Via GitHub UI
1. Go to release page
2. Click "Edit release"
3. Drag & drop files
4. Click "Update release"

### Via gh CLI
```bash
gh release upload v1.0.0 pocx_miner-custom-build.exe
```

## Troubleshooting

### Workflow fails during build
- Check build logs in Actions tab
- Verify Cargo.lock is committed
- Ensure all dependencies are available

### Missing artifacts
- Check individual build job logs
- Verify artifact upload step succeeded
- Check artifact retention (7 days for test builds)

### Wrong version in binary names
- Ensure tag format matches `v*.*.*` pattern
- Check version extraction logic in workflow

### Checksums don't match
- Re-download files (may be corrupted)
- Verify download wasn't interrupted
- Check that you're using the right checksum file

## Next Steps

After successful first release:

1. Add release badge to README:
   ```markdown
   [![Release](https://img.shields.io/github/v/release/PoC-Consortium/pocx)](https://github.com/PoC-Consortium/pocx/releases)
   ```

2. Consider adding:
   - CHANGELOG.md for manual release notes
   - git-cliff for automated changelogs
   - Version bump script for automation

3. Document release process in CONTRIBUTING.md

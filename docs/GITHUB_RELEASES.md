# GitHub Releases In This Fork

Pushing commits does not create entries in the GitHub `Releases` page.

This fork now includes a separate workflow:

- `.github/workflows/fork-release.yml`

It creates a GitHub release manually from the Actions tab and uploads:

- `AmneziaVPN_windows_unpacked.zip`
- `AmneziaVPN-arm64-v8a-debug.apk`

## How to publish

1. Open `Actions`.
2. Select `Fork Release`.
3. Click `Run workflow`.
4. Fill:
   - `tag`: for example `fork-2026-04-15`
   - `name`: for example `RU bypass preview`
5. Wait for the workflow to finish.

After that, the assets will appear in the repository `Releases` page.

# Fork Releases

This fork keeps local release artifacts outside git history.

## Local staging

- Local release bundles are exported into `local-releases/`.
- `local-releases/` is ignored by git so APKs, unpacked Windows bundles and local notes do not pollute commits.
- If the original Windows installer build was used, the staged export also picks up `AmneziaVPN_x64.exe` and `AmneziaVPN_x64.msi` from the repo root.
- Use `deploy/export_local_release.ps1` after a local build to copy known outputs into a timestamped folder.

Example:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\export_local_release.ps1 -Version 4.8.15.0-ru-bypass
```

By default the script looks for:

- `C:\src\Amnezia-unpacked`
- `AmneziaVPN_x64.exe` in the repository root
- `AmneziaVPN_x64.msi` in the repository root
- `C:\src\Amnezia-build\client\Release\AmneziaVPN.exe`
- `C:\src\Amnezia-build\service\server\Release\AmneziaVPN-service.exe`
- `C:\src\Amnezia-android-build\client\android-build\build\outputs\apk\debug\AmneziaVPN-arm64-v8a-debug.apk`

## GitHub releases

`deploy/deploy_s3.sh` now uses the current GitHub repository automatically:

- `GITHUB_RELEASE_REPO` if it is set
- otherwise `GITHUB_REPOSITORY`
- otherwise the upstream fallback `amnezia-vpn/amnezia-client`

That makes the release helper usable from a fork without hardcoding the upstream repository name.

The GitHub `Fork Release` workflow now publishes:

- `AmneziaVPN_windows_installer_x64.exe`
- `AmneziaVPN_windows_installer_x64.msi`
- `AmneziaVPN_windows_unpacked.zip`
- `AmneziaVPN-arm64-v8a-debug.apk`

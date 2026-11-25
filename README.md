# Bubble Bobble for Kakao — Custom Preservation Server & Toolkit

A zero-dependency Python 3 preservation server, automatic APK patcher, and GUI level editor for the shut-down Unity mobile game **Bubble Bobble for Kakao** (`버블보블 for Kakao`), reverse-engineered from its decompiled client source.

---

## Project Files

| File / Folder | Purpose |
| :--- | :--- |
| `bbfk_server.py` | Zero-dependency HTTP/MsgPack/Protobuf preservation server with persistent saves (`bbfk_save.json`) |
| `patch_apk.py` | Automatic `.apk` / `Assembly-CSharp.dll` patcher (sets server `ip:port`, enables Guest Mode, applies sprite fallbacks) |
| `bbfk_level_editor.py` | Tkinter GUI level editor for creating and editing multi-section `32×34` stage JSON files |
| `levels/` | Custom stage JSON files (`stage_01.json`–`stage_40.json`), automatically chunked into 10-stage episodes (`episode_001.bin`–`episode_004.bin`) |
| `bbfk_save.json` | Auto-generated player save file (currencies, hearts, inventory, character stats, stage unlocks, best scores) |

---

## Features

- **Zero External Dependencies**: Server, patcher, and level editor run purely on the Python 3 standard library (`http.server`, `zlib`, `base64`, `json`, `struct`, `zipfile`, `tkinter`).
- **Exact Binary Wire Protocol (`NRequestBase` / `MsgPack.BoxingPacker`)**:
  - Decodes `POST` form `param` payloads (`URL-safe Base64 -> zlib -> MessagePack`).
  - Encodes `{"bin_response": "..."}` responses using legacy MessagePack raw string framing compatible with `BoxingPacker`.
- **Encrypted Episode `.bin` Compiler (`SerializeEpisodeData` + `BinaryConverter`)**:
  - Serializes `SerializeEpisodeData` Protobuf payloads and encrypts them with `BinaryConverter.Encryption` and the 256-byte `MyRand` table.
  - Automatically loads `levels/*.json` (if present) and chunks every 10 stages into its own episode (`episode_001.bin`, `episode_002.bin`, ...) to match the client's 10-button-per-episode map layout, or falls back to 10 built-in multi-part stages.
- **Procedural PNG Resource Serving**: Serves pure-Python generated `1280×720` / `512×512` PNGs (`ep_map_01.png`, `ep_bg_01.png`, `ep_end.png`, `mp_0021_0.png`) over `/resource/resources/Android/`.
- **Populated Shop, Gacha & Inventory**: Includes 9 pre-level items (`Bubble Speed`, `Rapid Fire`, `Bubble Range`, `Move Speed`, `Extend Time`, `Auto Collect`, `Attack Up`, `Boss HP Down`, `Extra Life +1`), 4 heart/coin shop packs, `99/99` starting hearts with 1-second recovery, starter pet, and gacha/level-up handlers.
- **Persistent Progression (`bbfk_save.json`)**: Automatically saves and reloads player state across server restarts.

---

## Quick Start

### 1. Patch the APK

Run `patch_apk.py` with your server machine's LAN `ip:port` (for example, `192.168.0.71:8080`):

```bash
python3 patch_apk.py BBFK.apk 192.168.0.71:8080 -o BBFK_patched.apk
```

Then sign `BBFK_patched.apk` (for example with `uber-apk-signer` or `apksigner`) before installing on Android. On Android 9+, ensure `android:usesCleartextTraffic="true"` is set on `<application>` in `AndroidManifest.xml` so Unity's `WWW` downloader can fetch `/resource/` files over HTTP.

`patch_apk.py` also accepts a standalone `Assembly-CSharp.dll`:

```bash
python3 patch_apk.py Assembly-CSharp.dll 192.168.0.71:8080 -o Assembly-CSharp_patched.dll
```

### 2. Start the Server

```bash
python3 bbfk_server.py --host 0.0.0.0 --port 8080 --public-host http://192.168.0.71:8080
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--host` | `0.0.0.0` | Interface to bind the HTTP server to |
| `--port` | `8080` | TCP port to listen on |
| `--public-host` | `http://127.0.0.1:<port>` | Base URL returned to the client for `/resource/` downloads |
| `--levels-dir` | `levels` | Directory containing custom stage `.json` files |

Delete `bbfk_save.json` at any time to reset progression.

### 3. Edit or Add Custom Levels

Place custom stage JSON files (or extract the 100-level pack) into `levels/` next to `bbfk_server.py`, or launch the GUI editor:

```bash
python3 bbfk_level_editor.py
```

- Use the tabs to add, duplicate, or remove map sections within a stage.
- Left-click/drag on the `32×34` grid to paint or erase tiles and place `Player 1`, `Pet (Player 2)`, `Enemies`, `Items`, and `Bubble Holes`.
- Right-click any object (or use **Select / Inspect**) to edit its properties, then click **Save to levels/** and restart `bbfk_server.py` (the server bumps `episode_version` automatically so the client re-downloads updated `.bin` packs).

---

## Protocol Overview

| Path | Method | Format | Purpose |
| :--- | :--- | :--- | :--- |
| `/index.php/<endpoint>` | `POST` | `param` form field (`urlsafe_b64(zlib(msgpack))`) -> `{"bin_response": "..."}` | Game API (boot, master data, login, stages, shop, gacha, missions) |
| `/resource/resources/<Platform>/<file>` | `GET` | Raw binary (`.bin` / `.png`) | Encrypted `SerializeEpisodeData` level packs and stage/map PNGs |
| `/view/a/policy_service`, `/view/a/policy_privacy` | `GET` | HTML | Local policy pages for the consent webview |

---

## Known Limitations

- **Original Server AssetBundles Missing**: Unity 4.x `.unity3d.and` AssetBundles (Bubblun's Spine rig, collection book models, and some UI/background bundles) were only hosted on the original CDN and are not included. `patch_apk.py` routes `Player` to `isSpine: false` using the bundled `root/game/enemy/zenchan` sprite sheet and remaps `bubble0` to `bubble1`, which can cause occasional blank frames during animations not present on the enemy sheet.
- **Single-User Local Save**: `bbfk_server.py` models a single local player (`user_id: 100001`) backed by `bbfk_save.json`; social features (Kakao friends, rankings, mail) return empty lists.

---

## Disclaimer

This project is intended strictly for software preservation and educational reverse-engineering of a discontinued game. No copyrighted original server binaries or proprietary CDN assets are included.
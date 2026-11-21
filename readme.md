# Bubble Bobble for Kakao — Custom Preservation Server

A zero-dependency Python 3 mock server for the shut-down Unity mobile game **Bubble Bobble for Kakao** (`버블보블 for Kakao`), reverse-engineered from its decompiled client source (`BBFK_sourcecode`).

It implements the game's binary wire protocol, master data endpoints, persistent player progression, and procedural encrypted episode `.bin` level generation so the client can boot, log in via Guest Mode, browse the shop/gacha/character menus, and play through multi-part stages.

---

## Features

- **Zero External Dependencies**: Uses only the Python 3 standard library (`http.server`, `zlib`, `base64`, `json`, `struct`, `threading`).
- **Exact Wire Protocol (`NRequestBase` / `MsgPack.BoxingPacker`)**:
  - Decodes `POST` form `param` payloads (`URL-safe Base64 -> zlib -> MessagePack`).
  - Encodes `{"bin_response": "..."}` responses using legacy MessagePack raw string framing compatible with `BoxingPacker`.
- **Encrypted Episode `.bin` Generator (`SerializeEpisodeData` + `BinaryConverter`)**:
  - Dynamically builds Protobuf-serialized `SerializeEpisodeData` binaries (schema extracted from `MySerializeDll.dll`) and encrypts them using `BinaryConverter.Encryption` and the 256-byte `MyRand` table.
  - Generates **10 multi-part stages** (2–3 sub-maps each + bonus maps) across **8 distinct 32×34 tile layouts** with jump-reachable platforms and varied enemy spawns (`Zen-chan`, `Banebou`, `Mighta`, `Hidegons`, `Monsta`, `Drunk`, `Pulpul`, `Invader`).
- **Procedural PNG Resource Serving**: Serves pure-Python generated `1280×720` / `512×512` PNGs (`ep_map_01.png`, `ep_bg_01.png`, `ep_end.png`, `mp_0021_0.png`) over `/resource/resources/Android/`.
- **Persistent Progression (`bbfk_save.json`)**: Automatically saves and reloads currencies, hearts, level/XP, inventory, character stats, tutorial state, and unlocked/cleared stages with best scores.
- **Populated Shop, Gacha & Inventory**: Includes 9 pre-level items (`Bubble Speed`, `Rapid Fire`, `Bubble Range`, `Move Speed`, `Extend Time`, `Auto Collect`, `Attack Up`, `Boss HP Down`, `Extra Life +1`), 4 heart/coin shop packs, starter pet, and gacha/level-up handlers.

---

## Requirements

- Python 3.8+
- Patched Android APK (see **Client Setup** below) on the same LAN as the server

---

## Quick Start

1. Find your machine's LAN IP address (for example, `192.168.0.71`).
2. Start the server, passing `--public-host` so `bbsystem/start` advertises a reachable `resources_host` to the phone:

```bash
python3 bbfk_server.py --host 0.0.0.0 --port 8080 --public-host http://192.168.0.71:8080
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--host` | `0.0.0.0` | Interface to bind the HTTP server to |
| `--port` | `8080` | TCP port to listen on |
| `--public-host` | `http://127.0.0.1:<port>` | Base URL returned to the client for `/resource/` downloads |

Player progress is saved automatically to `bbfk_save.json` in the working directory. Delete `bbfk_save.json` to reset progression.

---

## Client Setup (APK / `Assembly-CSharp.dll` Notes)

Because the original KakaoTalk auth servers and CDN AssetBundles are offline, the client requires a few patches in `assets/bin/Data/Managed/Assembly-CSharp.dll` (via `dnSpy`) and `AndroidManifest.xml`:

1. **Point Endpoints to Your Server (`Global.SysDef.URL`)**:
   - Update `APP_HOST` to `http://<YOUR_LAN_IP>:8080/index.php/` and `APP_HOST_DATA` to `http://<YOUR_LAN_IP>:8080/resource/`.
   - Keep `Global.SysDef.isUseLocalResouce()` returning `false` so the client downloads `.bin` levels and map PNGs from the server.
2. **Enable Guest Login (`Global.SysDef.GetAndroid_GuestMode`)**:
   - Return `true` so the Guest Login button appears on the title screen and bypasses KakaoTalk authentication.
3. **(Optional) Allow Cleartext HTTP on Android 9+ (`AndroidManifest.xml`)**:
   - Set `android:usesCleartextTraffic="true"` on `<application>` so Unity's `WWW` downloader can fetch `/resource/` files over `http://`.
4. **Missing Character Spine AssetBundle Workaround (`Game.EndStateLoad`, `Game.getBubblenTextureName`, `Game.getBubbleTextureName`)**:
   - The original `Bubblen1_1.unity3d.and` Spine AssetBundle is not included in the APK. Passing `isSpine: false` to `Player.Create(...)` in `Game.EndStateLoad()`, returning a bundled 2D sprite sheet (such as `root/game/enemy/zenchan`) in `Game.getBubblenTextureName()`, and remapping `root/game/bubble0` to `root/game/bubble1` in `Game.getBubbleTextureName()` allows the player and bubbles to render in-game.

You can use the automatic patcher (patch_apk.py), change parameters in its bat launcher file.
---

## Protocol Overview

| Path | Method | Format | Purpose |
| :--- | :--- | :--- | :--- |
| `/index.php/<endpoint>` | `POST` | `param` form field (`urlsafe_b64(zlib(msgpack))`) -> `{"bin_response": "..."}` | Game API (boot, master data, login, stages, shop, gacha, missions) |
| `/resource/resources/<Platform>/<file>` | `GET` | Raw binary (`.bin` / `.png`) | Encrypted `SerializeEpisodeData` level packs and stage/map PNGs |
| `/view/a/policy_service`, `/view/a/policy_privacy` | `GET` | HTML | Local policy pages for the consent webview |

---

## Known Limitations

- **Original Server AssetBundles Missing**: Unity 4.x `.unity3d.and` AssetBundles (Bubblun's Spine rig, collection book models, and some UI/background bundles) were only hosted on the original CDN and cannot be reconstructed from source alone.
- **Placeholder Player Sprite**: Using a bundled enemy sprite sheet (`zenchan`) for `Player` with `isSpine: false` causes occasional invisible frames where Bubblun's animation table references rows beyond the enemy sheet's height.
- **Single-User In-Memory Session**: `bbfk_server.py` models a single local player (`user_id: 100001`) backed by `bbfk_save.json`; social features (Kakao friends, rankings, mail) return empty lists.

---

## Disclaimer

This project is intended strictly for software preservation and educational reverse-engineering of a discontinued game. No copyrighted original server binaries or proprietary CDN assets are included.

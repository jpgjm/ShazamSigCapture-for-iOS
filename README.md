# ShazamSigCapture-for-iOS

iOS 版 Shazam アプリが Apple へ送る署名付きリクエストから

- `X-Apple-ActionSignature`
- `X-Request-Timestamp`

を平文で取り出し、**ST-Handlers 互換の `key.json`** としてアプリ内に書き出す
iOS Tweak（Theos + Logos）。**[ShazamSigCapture (Android)](../) の iOS 移植**で、
SigProbe / Shazam-API (Node) の **v2 バックエンド**へそのまま供給できる。

---

## なぜ必要か

Android 版と同じ。`match/v2` は Apple の API トークンを要求し、そのトークンは
端末上で生成される `X-Apple-ActionSignature` に依存する。この署名は Apple の
ネイティブ実装（iOS では同梱の `AppleMediaServicesKit.framework`、Android では
`libAMSKit.so`）が生成するため自前再現は非現実的。第三者が配る `key.json` は
短命ですぐ 401 になる。**自分の端末の Shazam から新鮮な署名を直接抜く**ことで
外部依存を断つ。

---

## 仕組み（Android v1.4 との対応）

| | Android 版 | iOS 版（本 Tweak） |
|---|---|---|
| 署名生成 | `libAMSKit.so`（native） | `AppleMediaServicesKit.framework`（native） |
| 最終送信点 | `AMSOKHTTPNetworkProvider.submitRequest`（OkHttp） | **`NSURLSession` のタスク生成メソッド群** |
| 捕捉するもの | 署名注入済みの全ヘッダ | `NSURLRequest.allHTTPHeaderFields` |
| フック手段 | Xposed/LSPatch | Logos `%hook` |

**署名生成そのものには一切触れない**思想は同一。iOS Shazam の AMSKit は
`AMSC2PURLSessionTaskContext` を通じて最終的に `NSURLSession` でリクエストを送る
ため、そこを横取りすれば token / bag / media どの AMS リクエストでも確実に拾える。

捕捉は 2 系統：

- **(A) 本命** — `NSURLSession` の `dataTaskWithRequest:` / `uploadTaskWithRequest:` /
  `downloadTaskWithRequest:`（＋completionHandler 版）を `%hook`。送信直前なので
  ヘッダは確定済み。
- **(B) 保険** — `NSMutableURLRequest -setValue:forHTTPHeaderField:` を `%hook` し、
  署名ヘッダがセットされる瞬間を直接拾う（(A) を通らない経路対策。Android 版の
  Result フック相当）。

AMSKit の内部クラス名ではなく **iOS 標準の `NSURLSession` を対象にしている**ので、
Shazam / AMSKit のバージョンが上がっても壊れにくい。

---

## ビルド

GitHub Actions（`.github/workflows/release.yml`）が `v*.*.*` タグ push で
`make package` し、`.deb` を Release に上げる。手元でビルドするなら Theos を入れて：

```
make package         # rootless .deb → packages/
# 単体 dylib が欲しい場合
make                 # → .theos/obj/ に ShazamSigCapture.dylib
```

---

## 使い方

### A. LiveContainer（root 不要・今回の環境）

1. LiveContainer に **iOS Shazam（`com.shazam.Shazam`）を導入**しておく。
2. 本 Tweak の **`ShazamSigCapture.dylib`** を LiveContainer の
   **Tweaks フォルダ**に入れ、Shazam のコンテナに適用する
   （LiveContainer 設定 → 対象アプリの Tweaks でこの dylib を有効化）。
   > `.deb` を入れる場合は中の `Library/MobileSubstrate/DynamicLibraries/`（rootless
   > なら `/var/jb/...` 配下）から `.dylib` を取り出して使う。LiveContainer は
   > フィルタ plist を見ないため、**Shazam のコンテナにだけ**適用すれば対象は絞れる。
3. LiveContainer で Shazam を起動 → **「ShazamSigCapture 有効」アラート**が出れば注入成功。
4. **曲を 1 回認識**させる（トークン取得が走る）。成功すると署名取得アラートが出て、
   下記に書き出される：

   ```
   <Shazam コンテナ>/Documents/key.json
   <Shazam コンテナ>/Documents/last-request.json
   ```

   LiveContainer のデータコンテナ = このパスなので、**ファイルアプリ**か
   コンテナのエクスポートで取り出せる。

### B. TrollStore / 脱獄

- **脱獄（Dopamine 等）**：`.deb` を Sileo でインストール → Shazam を普通に起動して認識。
- **TrollStore**：Shazam の ipa に `ShazamSigCapture.dylib` を inject して再インストール、
  または脱獄環境の DynamicLibraries に配置。フィルタ plist（`com.shazam.Shazam`）で
  対象は Shazam のみに限定される。

`key.json` の中身は ST-Handlers と同じ schema：

```json
{
  "apple_action_signature": "AqHc...",
  "x_request_timestamp": "2026-08-11T09:47:41Z"
}
```

---

## 供給する

- **Shazam-API (Node)** … この `key.json` を自分でホストし、`ShazamV2Backend` の
  取得先 URL をそこへ向ける。あるいは取得部をローカル読み込みに差し替え。
- **SigProbe (iOS)** … `ShazamV2Backend.keyJSONURL` を自分のホスト先に変更するか、
  採取した 2 値を直接埋める。

---

## まず生存確認

1. Shazam 起動時に **「ShazamSigCapture 有効」アラート**が出るか。
   → 出れば dylib は Shazam プロセスに注入されている。
2. コンソール（Mac の Console.app / `idevicesyslog`）で：
   ```
   [ShazamSigCapture] injected (bundle=com.shazam.Shazam)
   [ShazamSigCapture] loaded into com.shazam.Shazam
   ```
   認識を走らせると：
   ```
   [ShazamSigCapture] ★署名検出 url=... timestamp=...
   [ShazamSigCapture] 書き出し完了 → .../Documents/key.json
   ```
3. **アラートもログも出ない** → 注入されていない。原因は本コードではなく導入側：
   - LiveContainer：Tweak が Shazam のコンテナで有効化されているか
   - TrollStore：inject 済みの ipa を確実に入れ替えたか

---

## 注意

- **署名は短命**。v2 を使うたびに新鮮な署名が要る。常用するなら Shazam を定期的に
  認識させて `key.json` を更新し続ける運用になる。
- 出力先は Shazam 自身のサンドボックス `Documents/` なので追加権限は不要。
- ホストアプリを巻き込まないよう、フック内は全て `@try/@catch` で保護してある。

---

## トラブルシュート

| 症状 | 確認 |
|---|---|
| アラートも key.json も出ない | コンソールに `injected` が出ているか。無ければ注入されていない（LiveContainer の Tweak 有効化 / inject 対象を確認） |
| アラートは出るが `★署名検出` が出ない | AMS 通信がまだ起きていない。曲を認識させる。それでも出なければ token がキャッシュ済み → Shazam のデータ消去 → コールドスタートで再取得を強制 |
| 署名は出るが v2 が 401 | 採取から時間が経ち失効。もう一度認識して採り直す |
| ヘッダ名が違う | Shazam のバージョン差。`last-request.json` の `headers` を見て、`SignatureKeys()` / `TimestampKeys()` の候補に実際のキーを足す |

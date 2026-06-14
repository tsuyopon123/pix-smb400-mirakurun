# PIX-SMB400 Mirakurun

PIX-SMB400（HiSilicon Hi3798CV200 搭載 Android TV）上で Mirakurun を実行し、BS4K（ISDB-S3）を受信するためのプロジェクトです。

<img width="1052" height="822" alt="image" src="https://github.com/user-attachments/assets/fd564f7a-a7b6-4b5c-941d-a226162a170c" />

## 免責事項

本プロジェクトのファイル・スクリプト・ドキュメントは、技術的な調査・学習を目的としています。
利用はすべて**自己責任**で行ってください。

- 本手順はメーカー非公式・非サポートの改造であり、実行した時点でメーカー保証は失われます。
- ブートローダや init への介入を伴うため、**デバイスが文鎮化（起動不能）する可能性**があります。
  実際に過去、特定の操作でデバイスが起動不能になった事例があります。
- 作者は、本プロジェクトの利用によって生じた**いかなる損害（デバイスの故障・データ消失・経済的損失・第三者への損害等を含むがこれに限らない）についても、  一切の責任を負いません。**
- 放送の受信・録画・復号は、利用者自身が正規に契約・受信権を持つ範囲で、私的利用の目的に限り行ってください。
関係する法令・契約・利用規約は各自の責任で遵守してください。

---

## 全体の流れ

```
Part 1: USB ブートで root を取る
  Step 1  ブートファイルをビルドして USB メモリを準備する
  Step 2  PIX-SMB400 を USB ブートで起動する
  Step 3  ADB で接続確認する

Part 2: Mirakurun のセットアップ
  Step 4  Alpine Linux + Node.js をセットアップする
  Step 5  Mirakurun をデプロイする
  Step 6  バイナリをビルドしてデプロイする
  Step 7  ACAS マスターキーを設定する

Part 3: 起動・確認
  Step 8  Mirakurun を起動する
  Step 9  BS4K ストリームを確認する
```

---

## 必要なもの

| 項目 | 内容 |
|------|------|
| PIX-SMB400 本体 | USB ブートピンにアクセスできる状態 |
| USB メモリ | FAT32 フォーマット、1 GB 以上 |
| kernel.img | ファームウェアから抽出した PIX-SMB400 のカーネルイメージ。ブートファイルのビルドに使用 |
| ビルド環境 | Docker（ブートファイル用）、`gcc-arm-linux-gnueabi` + `libssl-dev`（バイナリのビルド用） |
| ACAS マスターキー | 64 文字の hex |

---

## ディレクトリ構成

```
.                                    （リポジトリのルート）
├── README.md                        このファイル
├── BOOT.md                          USB ブートイメージの仕組みと再ビルド手順
├── Makefile                         デプロイ・運用コマンド集
├── boot/                            USB ブート用ファイル（ビルド手順は BOOT.md）
│   ├── make_usb_boot.py             bootargs.bin / root_rsa_pub_crc.bin 生成スクリプト
│   ├── patch_init.py                init バイナリパッチスクリプト（SELinux bypass 等）
│   ├── build_initramfs.sh           initramfs_patched.uimg ビルドスクリプト
│   └── initramfs_overlay/           initramfs オーバーレイファイル
├── bin/                             ビルドしたバイナリの出力先（make build-bins で生成）
├── include/openssl/                 b61dec ビルド用 OpenSSL 設定ヘッダ
├── patches/                         デプロイ時に適用するパッチ（@node-rs/crc32 の JS シム）
├── scripts/
│   ├── smb400-tuner.sh              Mirakurun チューナーコマンドラッパー
│   ├── start_mirakurun.sh           Mirakurun 起動スクリプト（手動実行用）
│   ├── stop_android_tv.sh           Android TV 不要プロセス停止
│   ├── crash_guard.sh               クラッシュ監視ウォッチドッグ
│   └── setup_proot.sh               Alpine + Node.js 初回セットアップ
├── config/
│   ├── tuners.yml                   Mirakurun チューナー設定
│   ├── channels.yml                 BS4K チャンネル一覧（8ch）
│   └── server.yml                   Mirakurun サーバー設定
└── src/                             バイナリの C ソースコード（make build-bins でビルド）
    ├── b61dec.c                     ACAS BS4K デスクランブラー
    ├── tuner-stream-bs-ng.c         BS4K（ISDB-S3）チューナー
    └── startup.c                    Android PIE 用 _start エントリポイント
```

---

## Part 1: USB ブートでルートを取る

> **仕組みの詳細・各ファイルのビルド方法は [BOOT.md](BOOT.md) を参照してください。**

### Step 1: ブートファイルをビルドして USB メモリを準備する

**1-1. ブートファイルをビルドする**

USB メモリに必要な 3 ファイル（`bootargs.bin` / `root_rsa_pub_crc.bin` / `initramfs_patched.uimg`）を `boot/` のスクリプトで生成します。
`initramfs_patched.uimg` のビルドには、用意した `kernel.img` から取り出した initramfs を使用します。

```sh
# 1) bootargs.bin / root_rsa_pub_crc.bin を生成
cd boot
docker run --rm -v "$(pwd):/usb_boot" python:3.11-slim bash -c "
pip install pycryptodome -q
cd /usb_boot && python3 make_usb_boot.py
"

# 2) kernel.img から initramfs を取り出して initramfs_patched.uimg をビルド
cd ..
binwalk -e kernel.img
bash boot/build_initramfs.sh /path/to/_kernel.img.extracted/988000
```

**1-2. FAT32 でフォーマットする**

```sh
sudo mkfs.fat -F 32 -n PIXBOOT /dev/sdX1
```

**1-3. USB メモリをマウントする**

```sh
sudo mkdir -p /mnt/PIXBOOT
sudo mount -o uid=$(id -u),gid=$(id -g) /dev/sdX1 /mnt/PIXBOOT
sudo chown $USER:$USER /mnt/PIXBOOT
```

**1-4. ブートファイルを USB メモリにコピーする**

```sh
# 手動でコピー
cp boot/bootargs.bin           /mnt/PIXBOOT/
cp boot/root_rsa_pub_crc.bin   /mnt/PIXBOOT/
cp boot/initramfs_patched.uimg /mnt/PIXBOOT/
```

USB メモリのルートに以下の 3 ファイルが置かれていれば OK です:

```
PIXBOOT/
├── bootargs.bin
├── root_rsa_pub_crc.bin
└── initramfs_patched.uimg
```

アンマウントして USB メモリを取り出します。

```sh
sudo umount /mnt/PIXBOOT
```

---

### Step 2: PIX-SMB400 を USB ブートで起動する

**2-1. 事前準備**

- PIX-SMB400 の電源を切る
- USB Boot ピン（基板上）にアクセスできる状態にする
- USB メモリを PIX-SMB400 の USB ポートに挿入する
- LAN ケーブルを接続する

**2-2. USB ブートピンをショートしながら電源を投入する**

1. USB Boot ピンをショートした状態を維持しながら電源を入れる
   <img width="1575" height="1181" alt="image" src="https://github.com/user-attachments/assets/09c1fc0b-332a-4d23-bf2b-5097678871e6" />

3. BootROM が USB メモリを検出し、外部 RSA 鍵で検証を行う
4. カスタム initramfs でシステムが起動する

---

### Step 3: ADB で接続確認する

起動後 30 秒ほど待ってから接続します。

**3-1. デバイスの IP アドレスを確認する**

デバイスが DHCP で取得した IP アドレスをシリアルコンソールまたは arp-scan 等で確認します。
シリアルコンソールで確認する場合、 `init_pix_netdbg.sh` が `PIXDBG: *** ADB: adb connect <デバイスのIPアドレス>:5555 ***` をカーネルログに出力しています。

**3-2. ADB 接続**

```sh
adb connect <デバイスのIPアドレス>:5555
adb -s <デバイスのIPアドレス>:5555 shell id
# → uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc) context=u:r:su:s0
```

`uid=2000(shell)` と表示された場合は eMMC から通常ブートしています（USB ブートを再確認）。

---

## Part 2: Mirakurun のセットアップ

> セットアップ以降は USB メモリを挿入して電源を入れるだけで、`mirakurun_proxy` サービスが起動時に Mirakurun を自動起動します（`make start` は不要）。
> ただし、安全のためクラッシュ時の自動再起動はしません。停止した場合は `make start` か再起動で復帰してください。

---

### Step 4: Alpine Linux + Node.js をセットアップする

デバイスにインターネット接続が必要です。コマンドはリポジトリのルートで実行します。

```sh
make setup-runtime ADB_TARGET=<デバイスのIPアドレス>:5555
```

Alpine ARM32 minirootfs のダウンロードと Node.js のインストールを自動で行います。
完了まで 3〜5 分かかります。

完了確認:

```sh
adb -s <デバイスのIPアドレス>:5555 shell \
  "chroot /data/local/tmp/mirakurun-root /bin/sh -c \
   'export PATH=/usr/sbin:/usr/bin:/sbin:/bin; node --version'"
# → v20.x.x などが返ること
```

---

### Step 5: Mirakurun をデプロイする

PC 側で Mirakurun をビルドしてからデバイスに転送します。

```sh
# リポジトリのルートに tmp/ を作ってクローン・ビルド
git clone https://github.com/tsuyopon123/Mirakurun-BS4K.git tmp/Mirakurun-BS4K
cd tmp/Mirakurun-BS4K && npm install && npm run build && cd ../..

# デバイスにデプロイ
make deploy-mirakurun ADB_TARGET=<デバイスのIPアドレス>:5555
```

Mirakurun のコードと設定ファイルがデバイスの `/data/local/tmp/mirakurun/` にコピーされます。

---

### Step 6: バイナリをビルドしてデプロイする

**6-1. バイナリをビルドする**

`src/` の C ソースからバイナリ（`tuner-stream-bs-ng` / `b61dec`）をビルドします。
リンクには実機の Android システムライブラリが必要なため、 `make build-bins` が ADB 経由で自動取得します（デバイスが USB ブート中であること）。

```sh
# 要件: sudo apt install gcc-arm-linux-gnueabi libssl-dev
make build-bins ADB_TARGET=<デバイスのIPアドレス>:5555
```

**6-2. バイナリ・スクリプト・設定をデプロイする**

```sh
make push-all ADB_TARGET=<デバイスのIPアドレス>:5555
```

以下をデバイスにコピーします:
- `bin/tuner-stream-bs-ng` — BS4K チューナー
- `bin/b61dec` — デスクランブラー
- `scripts/*.sh` — 各種スクリプト
- `config/*.yml` — Mirakurun 設定

> 設定やスクリプトを更新した場合は `make push-all` だけ再実行します。
> バイナリ自体を変更した場合は `make build-bins` から実行します。

---

### Step 7: ACAS マスターキーを設定する

BS4K デスクランブルには ACAS マスターキー（64 文字 hex）が必要です。

```sh
# デバイスのシェルで実行（64HEX_KEY を実際のキーに置き換える）
adb -s <デバイスのIPアドレス>:5555 shell

echo '64HEX_KEY' > /data/local/tmp/.acas_key
chmod 600 /data/local/tmp/.acas_key

# 確認（65 = 64 文字 + 改行）
wc -c /data/local/tmp/.acas_key
```

---

## Part 3: 起動・確認

### Step 8: Mirakurun を起動する

```sh
make start ADB_TARGET=<デバイスのIPアドレス>:5555
```

正常起動時:

```
{"current":"4.0.0-...","latest":"..."}
```

---

### Step 9: BS4K ストリームを確認する

```sh
make test ADB_TARGET=<デバイスのIPアドレス>:5555
```

出力例（正常）:

```
Streaming BS4K 45168 for 5s...
0000000 7f 02 00 60 60 00 00 00 ...
```

- `7f 02 ...` または `7f 03 ...` → **正常**（IPv4 / IPv6 TLV コンテンツ）
- `7f ff 00 00 ...` → 未復号（b61dec の ACAS 認証失敗）→ Step 7 を確認
- 出力なし → チューナーが応答していない → `make log` でログを確認

### ffplay でリアルタイム視聴

再生にはmmt/tlvに対応した [FFmpeg](https://github.com/superfashi/FFmpeg) が必要です。

```sh
ffplay http://<デバイスのIPアドレス>:40772/api/channels/BS4K/45168/stream
```

### EPGStation で録画・視聴

BS4K に対応した EPGStation フォークを使うと、Web UI から録画予約・視聴が行えます。

- リポジトリ: [tsuyopon123/EPGStation](https://github.com/tsuyopon123/EPGStation)

EPGStation をセットアップする際に `mirakurunPath` を `http://<デバイスのIPアドレス>:40772/` に設定してください。

---

## サービス登録と EPG について

初回起動後、Mirakurun は `channels.yml` で `serviceId` を指定した各チャンネルを
順次チューニングしてサービスを自動登録します。**全チャンネルが揃うまで数分**かかります
（1 チューナーで順番にチューニングするため）。

```sh
# 登録されたサービスを確認
curl -s http://<デバイスのIPアドレス>:40772/api/services | python3 -m json.tool
```

- サービスが登録されると、それを対象に **EPG Gatherer / Service Updater** が動き出します
  （登録サービスが 0 件のうちは、これらのジョブは対象が無いため即終了します）。
- **BS4K はチャンネルスキャン非対応**です。サービス登録には `channels.yml` の各エントリに
  `serviceId` の明示が必須です（`channel` はチューナへ渡すストリーム ID、`serviceId` は
  SDT 上の実サービス ID で、両者は別の値）。
- トランスポンダの初回チューニング時、ウォームアップで稀にサービスを取り逃すことがあります
  （ストリーム先頭の `7f ff`）。その場合は `make start` で再起動すれば取得されます
  （登録済みサービスは DB から復元されるため再チューニングされません）。

> **再起動について**: Web UI の Restart ボタンはこの構成（pm2／Docker なし）では使えず
> 500 を返します。再起動はホストから `make restart` を使ってください。

---

## コマンド

```sh
make start    # Mirakurun 起動
make stop     # 停止（チューナー・デスクランブラーも含む）
make restart  # 再起動
make log      # ログ確認（最新 50 行）
make test     # BS4K 疎通テスト
make push-all # バイナリ・スクリプト・設定を更新

# デバイスの IP アドレスを指定する場合
make start ADB_TARGET=192.168.1.100:5555
```

---

## 注意事項

### OEM サービスと ACAS 競合

OEM チューナーサービス（`pix_airtuner`）が起動中は ACAS を占有するため、
`b61dec` が失敗します（`GetCkc failed: -4`）。

`start_mirakurun.sh` は起動時に自動で停止します。
再起動後に OEM サービスが復帰した場合は手動で停止:

```sh
adb -s <デバイスのIPアドレス>:5555 shell "stop pix_airtuner; stop airtuner; stop airtuner_4k"
```

### メモリ管理（crash_guard）

`crash_guard.sh` が自動起動し以下を監視します:

- `crash_dump32` フォーク爆弾（Android 8 のクラッシュダンプ暴走）
- MemAvailable < 350 MB → Node.js を強制終了

Node.js のヒープは `--max-old-space-size=256` で制限されています。

### USB Boot ファイルのビルド

`bootargs.bin` / `root_rsa_pub_crc.bin` / `initramfs_patched.uimg` のビルド手順・
オーバーレイのカスタマイズ方法は [BOOT.md](BOOT.md) を参照してください。

---

## トラブルシューティング

```sh
# ログ確認
make log ADB_TARGET=<デバイスのIPアドレス>:5555

# crash_guard ログ
adb -s <デバイスのIPアドレス>:5555 shell "tail -20 /data/local/tmp/crash_guard.log"

# メモリ確認
adb -s <デバイスのIPアドレス>:5555 shell "grep MemAvailable /proc/meminfo"
```

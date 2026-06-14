# SMB400 Mirakurun-BS4K — デプロイ & 運用 Makefile
#
# 前提: デバイスが USB ブートで起動し ADB ルート取得済みであること。
# 初回のみ: Alpine + Node.js セットアップ (setup-runtime) と
#            Mirakurun JS デプロイ (deploy-mirakurun) が必要。
#
# 典型的な操作:
#   make push-all           バイナリ・スクリプト・設定を一括更新
#   make start              Mirakurun 起動
#   make stop               停止
#   make log                ログ確認
#   make test               BS4K ストリーム疎通確認

# ---------- 変更可能な設定 ----------
# ADB_TARGET 未指定時は adb devices から自動検出
# 複数台接続時は明示指定: make <target> ADB_TARGET=192.168.1.126:5555
ifndef ADB_TARGET
  _DETECTED := $(shell adb devices 2>/dev/null | awk '/\tdevice$$/{print $$1}')
  ifeq ($(words $(_DETECTED)),0)
    $(error No ADB device connected. Run: adb connect <ip>:<port>)
  else ifneq ($(words $(_DETECTED)),1)
    $(error Multiple ADB devices detected: $(_DETECTED) — set ADB_TARGET=<device>)
  else
    ADB_TARGET := $(_DETECTED)
  endif
endif
ADB        := adb -s $(ADB_TARGET)
DEVICE_IP  := $(firstword $(subst :, ,$(ADB_TARGET)))
DEVICE_TMP := /data/local/tmp
MIRAKURUN  := $(DEVICE_TMP)/mirakurun

# Mirakurun-BS4K JS ソース（初回デプロイ時のみ使用）
MIRAKURUN_SRC ?= tmp/Mirakurun-BS4K

# バイナリビルド設定
# 要件: gcc-arm-linux-gnueabi（sudo apt install gcc-arm-linux-gnueabi）
#       libssl-dev（b61dec の OpenSSL ヘッダ用）
CC_ARM       ?= arm-linux-gnueabi-gcc
ANDROID_LIBS := android-libs
# _TIME_BITS=32 / _FILE_OFFSET_BITS=32: 新しい Debian/Ubuntu のクロスツールチェーンは
# 64-bit time_t がデフォルトで __gettimeofday64 等を要求するが、Android bionic の
# libc.so は 32-bit time_t のシンボル (gettimeofday 等) しか持たないため明示的に 32-bit へ。
CFLAGS_ARM   := -march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3 \
                -pie -fPIE -fno-stack-protector -nostartfiles \
                -D_TIME_BITS=32 -D_FILE_OFFSET_BITS=32 \
                -Wl,-dynamic-linker,/system/bin/linker \
                -L$(ANDROID_LIBS) -Wl,-rpath-link,$(ANDROID_LIBS)
# ------------------------------------

.PHONY: build-bins android-libs \
        push-all push-bins push-scripts push-config \
        deploy-mirakurun setup-runtime \
        start stop restart log test help

# ---- ビルド (src/ → bin/) ----

# デバイスから Android システムライブラリを取得（初回のみ。ADB 接続が必要）
# bionic libc/libssl 等にリンクするため実機の .so を使用する。
android-libs:
	@mkdir -p $(ANDROID_LIBS)
	@for lib in libc.so libdl.so ld-android.so libssl.so libcrypto.so libm.so; do \
	    if [ ! -f $(ANDROID_LIBS)/$$lib ]; then \
	        echo "[*] pull /system/lib/$$lib"; \
	        $(ADB) pull /system/lib/$$lib $(ANDROID_LIBS)/$$lib; \
	    fi; \
	done

# src/ から bin/ のバイナリ（tuner-stream-bs-ng, b61dec）をビルド
build-bins: android-libs
	@mkdir -p bin
	@echo "[*] Building tuner-stream-bs-ng..."
	$(CC_ARM) $(CFLAGS_ARM) \
	    src/startup.c src/tuner-stream-bs-ng.c \
	    $(ANDROID_LIBS)/libc.so $(ANDROID_LIBS)/libdl.so $(ANDROID_LIBS)/ld-android.so \
	    -o bin/tuner-stream-bs-ng
	@echo "[*] Building b61dec..."
	$(CC_ARM) $(CFLAGS_ARM) -Wl,--no-as-needed \
	    -isystem /usr/include -isystem include \
	    src/startup.c src/b61dec.c \
	    $(ANDROID_LIBS)/libssl.so $(ANDROID_LIBS)/libcrypto.so \
	    $(ANDROID_LIBS)/libc.so $(ANDROID_LIBS)/libdl.so \
	    $(ANDROID_LIBS)/libm.so $(ANDROID_LIBS)/ld-android.so \
	    -o bin/b61dec
	@echo "[+] Built bin/tuner-stream-bs-ng and bin/b61dec"

# ---- デプロイ ----

push-bins:
	@echo "[*] Pushing binaries..."
	$(ADB) push bin/tuner-stream-bs-ng $(DEVICE_TMP)/tuner-stream-bs-ng
	$(ADB) push bin/b61dec             $(DEVICE_TMP)/b61dec
	$(ADB) shell chmod +x \
	    $(DEVICE_TMP)/tuner-stream-bs-ng \
	    $(DEVICE_TMP)/b61dec

push-scripts:
	@echo "[*] Pushing scripts..."
	$(ADB) push scripts/smb400-tuner.sh    $(DEVICE_TMP)/smb400-tuner.sh
	$(ADB) push scripts/start_mirakurun.sh $(DEVICE_TMP)/start_mirakurun.sh
	$(ADB) push scripts/stop_android_tv.sh $(DEVICE_TMP)/stop_android_tv.sh
	$(ADB) push scripts/crash_guard.sh     $(DEVICE_TMP)/crash_guard.sh
	$(ADB) shell chmod +x \
	    $(DEVICE_TMP)/smb400-tuner.sh \
	    $(DEVICE_TMP)/start_mirakurun.sh \
	    $(DEVICE_TMP)/stop_android_tv.sh \
	    $(DEVICE_TMP)/crash_guard.sh

push-config:
	@echo "[*] Pushing config..."
	$(ADB) shell mkdir -p $(MIRAKURUN)/config
	$(ADB) push config/tuners.yml   $(MIRAKURUN)/config/tuners.yml
	$(ADB) push config/channels.yml $(MIRAKURUN)/config/channels.yml
	$(ADB) push config/server.yml   $(MIRAKURUN)/config/server.yml

push-all: push-bins push-scripts push-config
	@echo "[+] Done. Run 'make start' to launch Mirakurun."

# 初回のみ: Mirakurun-BS4K JS ファイル一式をデプロイ
# $(MIRAKURUN_SRC) を GitHub からクローンしてビルド済みであること。
deploy-mirakurun:
	@echo "[*] Deploying Mirakurun JS to device..."
	$(ADB) shell mkdir -p $(MIRAKURUN)/config $(MIRAKURUN)/db $(MIRAKURUN)/logo-data
	$(ADB) push $(MIRAKURUN_SRC)/lib/          $(MIRAKURUN)/lib/
	$(ADB) push $(MIRAKURUN_SRC)/node_modules/ $(MIRAKURUN)/node_modules/
	$(ADB) push $(MIRAKURUN_SRC)/package.json  $(MIRAKURUN)/package.json
	$(ADB) push $(MIRAKURUN_SRC)/api.yml       $(MIRAKURUN)/api.yml
	@echo "[*] Applying @node-rs/crc32 JS shim (no musl-arm native build)..."
	$(ADB) push patches/node-rs-crc32-index.js \
	    $(MIRAKURUN)/node_modules/@node-rs/crc32/index.js
	$(ADB) push config/tuners.yml   $(MIRAKURUN)/config/tuners.yml
	$(ADB) push config/channels.yml $(MIRAKURUN)/config/channels.yml
	$(ADB) push config/server.yml   $(MIRAKURUN)/config/server.yml
	@echo "[+] Mirakurun JS deployed."

# 初回のみ: Alpine ARM32 + Node.js をデバイスに構築（インターネット接続必要）
setup-runtime:
	bash scripts/setup_proot.sh

# ---- 起動・停止 ----

start:
	@echo "[*] Stopping any existing session..."
	-$(ADB) shell "pkill -9 Mirakurun 2>/dev/null; \
	    kill -9 \$$(pgrep -f 'start_mirakurun[.]sh' 2>/dev/null) 2>/dev/null; \
	    pkill -9 b61dec 2>/dev/null; pkill -9 tunertest 2>/dev/null; true"
	@sleep 2
	@echo "[*] Starting Mirakurun..."
	$(ADB) shell "setsid sh $(DEVICE_TMP)/start_mirakurun.sh \
	    >> $(DEVICE_TMP)/mirakurun.log 2>&1 &"
	@echo "[*] 起動を待っています（最大 ~60 秒）..."
	@ok=0; for i in $$(seq 1 30); do \
	    if curl -s --max-time 5 http://$(DEVICE_IP):40772/api/version >/dev/null 2>&1; then ok=1; break; fi; \
	    sleep 2; \
	done; \
	if [ $$ok = 1 ]; then \
	    printf "[+] Mirakurun is up: "; curl -s --max-time 5 http://$(DEVICE_IP):40772/api/version; echo; \
	else \
	    echo "(まだ応答がありません — 'make log' で確認してください)"; \
	fi

stop:
	-$(ADB) shell "pkill -9 Mirakurun 2>/dev/null; \
	    kill -9 \$$(pgrep -f 'start_mirakurun[.]sh' 2>/dev/null) 2>/dev/null; \
	    pkill -9 b61dec 2>/dev/null; \
	    pkill -9 tunertest 2>/dev/null; \
	    pkill -9 -f tuner-stream 2>/dev/null; true"
	@echo "Stopped."

restart: stop start

# ---- 確認 ----

log:
	$(ADB) shell "tail -50 $(DEVICE_TMP)/mirakurun.log"

# BS4K 45168 から 5 秒受信して先頭バイトを表示
# 正常: 7f 02 ... または 7f 03 ... (IPv4/IPv6 TLV コンテンツ)
# 異常: 7f ff ... (Null TLV = 未復号) またはデータなし
test:
	@echo "Streaming BS4K 45168 for 5s..."
	@curl -s --max-time 8 http://$(DEVICE_IP):40772/api/channels/BS4K/45168/stream \
	    | od -v -t x1 2>/dev/null | head -4

# ---- ヘルプ ----

help:
	@echo ""
	@echo "SMB400 Mirakurun-BS4K デプロイ Makefile"
	@echo ""
	@echo "  make build-bins        src/ から bin/ のバイナリをビルド (初回のみ)"
	@echo "  make android-libs      デバイスから Android システムライブラリを取得"
	@echo "  make push-all          バイナリ・スクリプト・設定を一括デプロイ"
	@echo "  make push-bins         バイナリのみ (tuner-stream-bs-ng, b61dec)"
	@echo "  make push-scripts      スクリプトのみ (smb400-tuner.sh 等)"
	@echo "  make push-config       設定ファイルのみ (channels.yml 等)"
	@echo "  make deploy-mirakurun  Mirakurun JS 一式をデプロイ (初回のみ)"
	@echo "  make setup-runtime     Alpine + Node.js をデバイスに構築 (初回のみ)"
	@echo "  make start             Mirakurun 起動"
	@echo "  make stop              Mirakurun 停止"
	@echo "  make restart           再起動"
	@echo "  make log               ログ確認 (tail -50)"
	@echo "  make test              BS4K ストリーム疎通テスト"
	@echo ""
	@echo "デフォルト接続先: $(ADB_TARGET)"
	@echo "変更: make start ADB_TARGET=192.168.1.100:5555"
	@echo ""

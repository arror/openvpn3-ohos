#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
# Builds, updates (without clearing data), and runs the Native/TUN regression feature.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_ROOT="${ARKOVPN_APP_ROOT:-$PROJECT_ROOT/ohos}"
if [ ! -d "$APP_ROOT/entry" ]; then echo "Set ARKOVPN_APP_ROOT to the external app checkout" >&2; exit 2; fi
DEVECO_ROOT="${DEVECO_ROOT:-/Applications/DevEco-Studio.app/Contents}"
export DEVECO_SDK_HOME="${DEVECO_SDK_HOME:-$DEVECO_ROOT/sdk}"
export NODE_HOME="${NODE_HOME:-$DEVECO_ROOT/tools/node}"
HDC_BIN="${HDC_BIN:-$DEVECO_SDK_HOME/default/openharmony/toolchains/hdc}"
HVIGOR="$DEVECO_ROOT/tools/hvigor/bin/hvigorw"
RESULT_LOG="${RESULT_LOG:-/tmp/arkovpn-device-test.log}"
cd "$APP_ROOT"
bash "$HVIGOR" assembleHap --mode module -p product=default --no-daemon
bash "$HVIGOR" assembleHap --mode module -p product=default -p module=entry@ohosTest --no-daemon
"$HDC_BIN" install -r entry/build/default/outputs/default/entry-default-signed.hap
"$HDC_BIN" install -r entry/build/default/outputs/ohosTest/entry-ohosTest-signed.hap
"$HDC_BIN" shell aa test -b com.arror.ovpn -m entry_test -s unittest OpenHarmonyTestRunner -s timeout 60000 > "$RESULT_LOG" 2>&1
cat "$RESULT_LOG"
# aa test can exit zero even when a test fails. Check the reported result too.
rg -q 'Tests run: [0-9]+, Failure: 0, Error: 0, Pass: [1-9][0-9]*, Ignore: 0' "$RESULT_LOG"

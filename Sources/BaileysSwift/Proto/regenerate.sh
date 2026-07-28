#!/bin/bash
# Regenerates WAProto.pb.swift from the vendored WAProto.proto.
#
# Baileys' WAProto.proto has several enums whose first member isn't 0
# (protobufjs tolerates this; protoc's proto3 front-end does not). Re-run
# `fetch-and-patch.py` after pulling a fresh WAProto.proto from upstream
# Baileys to reapply the synthetic `<NAME>_UNSPECIFIED = 0` entries before
# regenerating.
set -euo pipefail
cd "$(dirname "$0")"
protoc --swift_out=. --swift_opt=Visibility=Public WAProto.proto

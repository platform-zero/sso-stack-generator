#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CLASSPATH_FILE="$ROOT/runtime-generator/build/generator-classpath.txt"

"$ROOT/gradlew" -q :runtime-generator:prepareGenerator
GENERATOR_CLASSPATH="$(<"$CLASSPATH_FILE")"
export STACK_GENERATOR_ROOT="$ROOT"
exec java -cp "$GENERATOR_CLASSPATH" \
  org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -script "$ROOT/runtime-generator/stack-generator.main.kts" \
  -no-stdlib -no-reflect -classpath "$GENERATOR_CLASSPATH" -- "$@"

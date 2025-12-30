#!/bin/bash
file_path=$(jq -r '.tool_input.file_path')
[[ "$file_path" == *.rs ]] && cargo fmt
exit 0

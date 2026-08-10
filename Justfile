ROOT := justfile_directory()

# Run the help recipe.
default: help

# List the available workspace recipes.
help:
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{ ROOT }}'
    just --list

# Show root Git and recursive submodule status.
status:
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{ ROOT }}'
    printf '%s\n' 'Root Git status:'
    git status --short --branch
    printf '%s\n' 'Recursive submodule status:'
    git submodule status --recursive

# Verify the controller workspace and its pinned development environment.
doctor:
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{ ROOT }}'

    require_command() {
        local command_name="$1"
        if ! command -v "$command_name" >/dev/null 2>&1; then
            printf 'doctor: required command not found: %s\n' "$command_name" >&2
            return 1
        fi
    }

    require_nix_shell() {
        if [[ -z "${IN_NIX_SHELL:-}" ]]; then
            printf '%s\n' 'doctor: enter the development shell with nix develop' >&2
            return 1
        fi
    }

    require_uv_environment() {
        if [[ "${UV_PYTHON_DOWNLOADS:-}" != 'never' ]]; then
            printf '%s\n' 'doctor: UV_PYTHON_DOWNLOADS must be never' >&2
            return 1
        fi
        if [[ "${UV_NO_MANAGED_PYTHON:-}" != '1' ]]; then
            printf '%s\n' 'doctor: UV_NO_MANAGED_PYTHON must be 1' >&2
            return 1
        fi
        if [[ "${UV_PYTHON:-}" != /nix/store/*/bin/python ]] || [[ ! -x "${UV_PYTHON}" ]]; then
            printf '%s\n' 'doctor: UV_PYTHON must be an executable Nix-store Python' >&2
            return 1
        fi
    }

    require_submodule_head() {
        local path="$1"
        local expected="$2"
        local actual

        if ! actual="$(git -C "$path" rev-parse --verify HEAD 2>/dev/null)"; then
            printf 'doctor: submodule is not initialized: %s\n' "$path" >&2
            return 1
        fi
        if [[ "$actual" != "$expected" ]]; then
            printf 'doctor: unexpected HEAD for %s: expected %s, got %s\n' \
                "$path" "$expected" "$actual" >&2
            return 1
        fi
    }

    require_command nix
    require_command git
    require_command just
    require_command python3
    require_command uv
    require_command jq
    require_command curl
    require_command ssh
    require_command rsync
    require_command shellcheck
    require_command treefmt
    require_nix_shell
    require_uv_environment
    require_submodule_head engine/ds4 df641a7c4358dd6ca3b5acb46cf884a7d42066ed
    require_submodule_head spark/ds4-on-spark 60c00afe24dc361c19e53037b599d98d27f32d7b

    printf '%s\n' 'doctor: controller workspace is ready'

# Print the development-tool versions.
tool-versions:
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{ ROOT }}'
    nix --version
    git --version
    just --version
    python3 --version
    uv --version
    jq --version
    curl --version | sed -n '1p'
    ssh -V 2>&1
    rsync --version | sed -n '1p'
    shellcheck --version | sed -n '1,2p'
    treefmt --version
    printf '\n'

# Initialize submodules and configure their required public remotes.
submodules:
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{ ROOT }}'

    verify_origin() {
        local path="$1"
        local expected="$2"
        local actual

        if ! actual="$(git -C "$path" remote get-url --all origin 2>/dev/null)"; then
            printf 'submodules: missing origin remote for %s\n' "$path" >&2
            return 1
        fi
        if [[ "$actual" != "$expected" ]]; then
            printf 'submodules: origin URL mismatch for %s: expected %s\n' \
                "$path" "$expected" >&2
            return 1
        fi
    }

    ensure_additional_remote() {
        local path="$1"
        local name="$2"
        local expected="$3"
        local actual

        if actual="$(git -C "$path" remote get-url --all "$name" 2>/dev/null)"; then
            if [[ "$actual" != "$expected" ]]; then
                printf 'submodules: %s URL mismatch for %s: expected %s\n' \
                    "$name" "$path" "$expected" >&2
                return 1
            fi
            return 0
        fi
        git -C "$path" remote add "$name" "$expected"
    }

    verify_registered_submodule_url() {
        local name="$1"
        local expected="$2"
        local actual
        local status

        if actual="$(git config --local --get-all "submodule.${name}.url" 2>/dev/null)"; then
            if [[ "$actual" != "$expected" ]]; then
                printf 'submodules: registered URL mismatch for %s: expected %s\n' \
                    "$name" "$expected" >&2
                return 1
            fi
        else
            status=$?
            if [[ "$status" -ne 1 ]]; then
                printf 'submodules: unable to read registered URL for %s\n' "$name" >&2
                return "$status"
            fi
        fi
    }

    verify_initialized_origin() {
        local path="$1"
        local expected="$2"

        if [[ -e "$path/.git" ]]; then
            verify_origin "$path" "$expected"
        fi
    }

    preflight_submodule() {
        local name="$1"
        local path="$2"
        local expected="$3"

        verify_registered_submodule_url "$name" "$expected"
        verify_initialized_origin "$path" "$expected"
    }

    preflight_submodule engine/ds4 engine/ds4 https://github.com/ZebulonRouseFrantzich/ds4.git
    preflight_submodule spark/ds4-on-spark spark/ds4-on-spark https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git

    git submodule update --init --recursive

    verify_origin engine/ds4 https://github.com/ZebulonRouseFrantzich/ds4.git
    ensure_additional_remote engine/ds4 upstream https://github.com/Entrpi/ds4.git
    ensure_additional_remote engine/ds4 antirez https://github.com/antirez/ds4.git
    verify_origin spark/ds4-on-spark https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
    ensure_additional_remote spark/ds4-on-spark upstream https://github.com/Entrpi/ds4-on-spark.git

# Check that every configured public remote fetch URL matches policy.
remotes-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{ ROOT }}'

    check_remote() {
        local path="$1"
        local name="$2"
        local expected="$3"
        local actual

        if ! actual="$(git -C "$path" remote get-url --all "$name" 2>/dev/null)"; then
            printf '%s %s expected=%s actual=<missing>\n' "$path" "$name" "$expected" >&2
            return 1
        fi
        if [[ "$actual" != "$expected" ]]; then
            printf '%s %s expected=%s\n' \
                "$path" "$name" "$expected" >&2
            return 1
        fi
        printf '%s %s %s\n' "$path" "$name" "$actual"
    }

    check_remote engine/ds4 origin https://github.com/ZebulonRouseFrantzich/ds4.git
    check_remote engine/ds4 upstream https://github.com/Entrpi/ds4.git
    check_remote engine/ds4 antirez https://github.com/antirez/ds4.git
    check_remote spark/ds4-on-spark origin https://github.com/ZebulonRouseFrantzich/ds4-on-spark.git
    check_remote spark/ds4-on-spark upstream https://github.com/Entrpi/ds4-on-spark.git

# Run the host-independent flake checks.
flake-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cd '{{ ROOT }}'
    nix flake check

# Target operations — Phase 01
# Explicit one-time migration for a qualified retired target lifecycle state.
target-migrate-state target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl migrate-state --target {{ quote(target) }}
target-doctor target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl doctor --target {{ quote(target) }}
target-sync target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl sync --target {{ quote(target) }}
target-build target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl build --target {{ quote(target) }}
target-serve target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl serve --target {{ quote(target) }}
target-status target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl status --target {{ quote(target) }}
target-logs target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl logs --target {{ quote(target) }}
target-stop target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl stop --target {{ quote(target) }}
target-smoke target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl smoke --target {{ quote(target) }}
target-cleanup target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl cleanup --target {{ quote(target) }}
target-bundle target="spark":
    cd '{{ ROOT }}' && python3 -m scripts.targetctl bundle --target {{ quote(target) }}

# Benchmark operations — Phase 02
bench-smoke target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-smoke --target {{ quote(target) }}
bench-smoke-local target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-smoke-local --target {{ quote(target) }}
bench-s1 target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-s1 --target {{ quote(target) }}
bench-s1-local-shipped target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-s1-local-shipped --target {{ quote(target) }}
bench-s1-local-plain target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-s1-local-plain --target {{ quote(target) }}
bench-s1-local-paired target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-s1-local-paired --target {{ quote(target) }}
bench-s2 target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-s2 --target {{ quote(target) }}
bench-s3 target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-s3 --target {{ quote(target) }}
bench-s5a target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-s5a --target {{ quote(target) }}
bench-s5b target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-s5b --target {{ quote(target) }}
bench-v1-baseline target="spark":
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl bench-v1-baseline --target {{ quote(target) }}
compare baseline candidate:
    cd '{{ ROOT }}' && uv run --frozen --project benchmarks python -m scripts.targetctl compare --baseline {{ quote(baseline) }} --candidate {{ quote(candidate) }}

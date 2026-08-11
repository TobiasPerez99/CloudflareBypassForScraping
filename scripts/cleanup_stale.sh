#!/bin/bash
# Limpieza de perfiles y navegadores Camoufox huérfanos dejados por solves abortados.
# Uso: ./scripts/cleanup_stale.sh [horas]   (default: 2)
# Pensado para correr DENTRO del contenedor cloudflare-bypass, o adaptando las rutas.
set -euo pipefail

MAX_AGE_HOURS="${1:-2}"
PROFILE_GLOB="/tmp/playwright_firefoxdev_profile-*"

echo "[cleanup] Borrando perfiles > ${MAX_AGE_HOURS}h en ${PROFILE_GLOB}"
find /tmp -maxdepth 1 -name 'playwright_firefoxdev_profile-*' -type d \
    -mmin +$((MAX_AGE_HOURS * 60)) -print -exec rm -rf {} + 2>/dev/null || true

echo "[cleanup] Matando procesos camoufox/node driver con más de ${MAX_AGE_HOURS}h de vida"
# etimes = tiempo de vida en segundos; matar los que superan el umbral.
THRESHOLD=$((MAX_AGE_HOURS * 3600))
ps -eo pid,etimes,comm | awk -v t="$THRESHOLD" \
    '$3 ~ /camoufox|node/ && $2 > t { print $1 }' \
    | while read -r pid; do
        echo "[cleanup] kill -TERM $pid"
        kill -TERM "$pid" 2>/dev/null || true
    done

echo "[cleanup] Listo."

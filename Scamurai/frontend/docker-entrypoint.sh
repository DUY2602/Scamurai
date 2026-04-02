#!/bin/sh
set -eu

cat > /app/dist/runtime-config.js <<EOF
window.__APP_CONFIG__ = {
  VITE_API_BASE_URL: "${VITE_API_BASE_URL:-}"
};
EOF

exec npm run preview -- --host 0.0.0.0 --port "${PORT:-4173}"

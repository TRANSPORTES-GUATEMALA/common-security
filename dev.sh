#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

KIND=library
PORT=
SERVICE=
ROUTE=
ACTION="${1:-help}"

usage() {
  echo "Uso: bash dev.sh {build|test|clean|check|install}"
  echo "Logs de cada accion: output/<accion>.txt (se sobrescriben)"
}

check_port() {
  if nc -G 2 -z 127.0.0.1 "$1" >/dev/null 2>&1; then
    echo "Puerto $1: OK"
  else
    echo "Puerto $1: NO DISPONIBLE"
    return 1
  fi
}

check_http() {
  local label="$1" url="$2" code
  code="$(curl --max-time 8 -s -o /dev/null -w '%{http_code}' \
    -H 'Accept: application/json' "$url" || true)"
  echo "$label: HTTP $code"
  [[ "$code" == '200' ]]
}

check_local() {
  local failed=0
  if [[ "$KIND" == library ]]; then
    [[ -f target/common-security-1.0-SNAPSHOT.jar ]] && echo 'JAR compilado: OK' || { echo 'JAR compilado: FALTA'; failed=1; }
    [[ -f "$HOME/.m2/repository/com/transportes/common-security/1.0-SNAPSHOT/common-security-1.0-SNAPSHOT.jar" ]] && echo 'JAR instalado en Maven local: OK' || { echo 'JAR instalado en Maven local: FALTA'; failed=1; }
  else
    check_port "$PORT" || failed=1
    if [[ "$KIND" == eureka ]]; then
      check_http 'Eureka API' 'http://127.0.0.1:8761/eureka/apps' || failed=1
    else
      check_http 'Registro Eureka' "http://127.0.0.1:8761/eureka/apps/$SERVICE" || failed=1
      if [[ "$KIND" == service ]]; then
        check_http 'Docs directo' "http://127.0.0.1:$PORT/api/v3/api-docs" || failed=1
        check_http 'Docs Gateway' "http://127.0.0.1:8080/api/$ROUTE/v3/api-docs" || failed=1
      fi
    fi
  fi
  return "$failed"
}

run_action() {
  case "$ACTION" in
    run)
      [[ -f .env ]] || { echo 'ERROR: falta .env; copiar .env.example y revisarlo'; return 1; }
      set -a
      # shellcheck disable=SC1091
      source ./.env
      set +a
      if [[ "$SERVICE" == FLEET-SERVICE && "${SPRING_PROFILES_ACTIVE:-}" != local ]]; then
        echo 'ERROR: Fleet sin GCS requiere SPRING_PROFILES_ACTIVE=local'
        return 1
      fi
      ./mvnw spring-boot:run
      ;;
    build)
      if [[ "$KIND" == library ]]; then
        mvn -DskipTests package
      else
        ./mvnw -DskipTests package
      fi
      ;;
    test)
      if [[ "$KIND" == library ]]; then
        mvn test
      else
        ./mvnw test
      fi
      ;;
    install)
      mvn clean install
      ;;
    clean)
      if [[ "$KIND" == library ]]; then
        mvn clean
      else
        ./mvnw clean
      fi
      ;;
    check) check_local ;;
  esac
}

case "$ACTION" in
  build|test|clean|check|install) ;;
  help|-h|--help) usage; exit 0 ;;
  *) usage; exit 2 ;;
esac

# Archivos locales: un solo log fijo por accion, reemplazado en cada ejecucion.
umask 077
mkdir -p output
LOG="output/$ACTION.txt"
: > "$LOG"
chmod 600 "$LOG"
run_action 2>&1 | tee "$LOG"

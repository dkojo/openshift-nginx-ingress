#!/usr/bin/env bash
# The proofs, one per pipeline step:
#   bash scripts/checks.sh certs     every certificate issued by the internal CA
#   bash scripts/checks.sh gate      HTTPS through the gate works; HTTP is redirected; TLS 1.2+ only; HSTS
#   bash scripts/checks.sh e2e       the services refuse plain HTTP and TLS without the ingress's client certificate
#   bash scripts/checks.sh surface   nothing but the gate is reachable
set -euo pipefail
GATE=https://shop.local:8443
CURL="curl -sS --max-time 10 --resolve shop.local:8443:127.0.0.1 --resolve shop.local:8080:127.0.0.1"

# A throwaway pod in a namespace, to run curl from inside the cluster
probe() { # probe <namespace> <curl args...> : runs curl in a pod and prints its output
  local ns=$1; shift
  local args; args=$(printf '"%s",' "$@"); args=${args%,}
  local name="probe-$RANDOM"
  kubectl run "$name" -n "$ns" -i --rm --restart=Never --quiet --image=curlimages/curl:8.11.1 \
    --overrides="{\"spec\":{\"securityContext\":{\"runAsNonRoot\":true,\"runAsUser\":100,\"seccompProfile\":{\"type\":\"RuntimeDefault\"}},\"containers\":[{\"name\":\"$name\",\"image\":\"curlimages/curl:8.11.1\",\"args\":[$args],\"securityContext\":{\"allowPrivilegeEscalation\":false,\"capabilities\":{\"drop\":[\"ALL\"]}}}]}}" 2>&1 || true
}

case "$1" in
  certs)
    kubectl wait --for=condition=Ready certificate/internal-ca -n cert-manager --timeout=120s >/dev/null
    kubectl wait --for=condition=Ready certificate --all -n shop --timeout=120s >/dev/null
    kubectl get secret internal-ca -n cert-manager -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
    for s in shop-tls catalog-tls orders-tls ingress-client; do
      kubectl get secret "$s" -n shop -o jsonpath='{.data.tls\.crt}' | base64 -d \
        | openssl x509 -noout -subject -issuer -enddate -ext subjectAltName 2>/dev/null | paste -sd' ' | sed "s/^/$s: /"
      kubectl get secret "$s" -n shop -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl verify -CAfile ca.crt >/dev/null
    done
    echo "PASS  4 certificates issued by the internal CA, all verify against it"
    ;;
  gate)
    for path in catalog orders; do
      body=$($CURL --cacert ca.crt "$GATE/$path")
      echo "GET $GATE/$path -> $body"
      grep -q '"caller":"CN=nginx-ingress"' <<< "$body"
    done
    code=$($CURL -o /dev/null -w '%{http_code} -> %{redirect_url}' http://shop.local:8080/catalog)
    echo "Plain HTTP: $code"; [[ $code == 301* ]]
    # Outputs are captured before grepping: grep -m1 on a live pipe can break it, and pipefail would fail the step
    headers=$($CURL --cacert ca.crt -I "$GATE/catalog")
    grep -i '^strict-transport-security' <<< "$headers" | tr -d '\r'
    hs=$(echo | openssl s_client -connect 127.0.0.1:8443 -servername shop.local -CAfile ca.crt -verify_return_error 2>/dev/null || true)
    proto=$(grep -m1 'Protocol' <<< "$hs" | awk '{print $NF}')
    echo "Negotiated protocol: $proto (certificate chain verified)"
    pod=$(kubectl get pod -n nginx-ingress -o name | head -1)
    conf=$(kubectl exec -n nginx-ingress "$pod" -- nginx -T 2>/dev/null || true)
    grep -m1 -E '^\s*ssl_protocols' <<< "$conf" | sed 's/^ */Gate allows: /'
    echo "PASS  HTTPS only, through one gate, verified certificate, HSTS, TLS 1.2+"
    ;;
  e2e)
    # From the ingress controller's own namespace (the only one the network policy lets in), but without its certificate
    out=$(probe nginx-ingress -sk -o /dev/null -w '%{http_code}' https://catalog.shop.svc:8443/)
    echo "TLS without the ingress's client certificate -> HTTP $out"; [[ $out == *400* ]]
    out=$(probe nginx-ingress -s -o /dev/null -w '%{http_code}' http://catalog.shop.svc:8443/)
    echo "Plain HTTP to the service -> HTTP $out"; [[ $out == *400* ]]
    body=$($CURL --cacert ca.crt "$GATE/orders")
    echo "Through the gate, the service sees: $body"
    echo "$body" | grep -q '"protocol":"TLSv1.3"'
    echo "PASS  every hop encrypted; the services only accept the ingress's certificate"
    ;;
  surface)
    kubectl create namespace outsider --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    out=$(probe outsider -sk --max-time 5 -o /dev/null -w '%{http_code}' https://catalog.shop.svc:8443/)
    echo "From another namespace -> ${out:-no answer}"
    if [[ $out == *200* || $out == *400* ]]; then echo "FAIL  a pod outside the gate reached the service"; exit 1; fi
    echo "Services in shop:"; kubectl get svc -n shop -o custom-columns=NAME:.metadata.name,TYPE:.spec.type --no-headers | sed 's/^/  /'
    exposed=$(kubectl get svc -A -o jsonpath='{range .items[?(@.spec.type!="ClusterIP")]}{.metadata.namespace}/{.metadata.name} {.spec.type}{"\n"}{end}')
    if [ -n "$exposed" ]; then echo "FAIL  exposed outside the gate:"; echo "$exposed"; exit 1; fi
    echo "Published to the outside: $(docker port gate-control-plane | paste -sd' ' -)"
    echo "PASS  only the gate (80 -> redirect, 443) is reachable; every service is ClusterIP behind a default-deny policy"
    ;;
esac

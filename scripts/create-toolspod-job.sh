#!/bin/bash

###
die() {
  echo "Died: $*"
  exit 1
}

###
yesno() {
  local str="$1"
  local userinput=""
  read -rp "$str (y/n*)? " userinput
  echo "$userinput" | grep -Piq '^\s*y(es)?\s*$' && return 0
  return 1
}

#
# MAIN
#
{
  oc whoami &>/dev/null || die "Not logged in"
  set -uo pipefail
  tmpf="$(mktemp)"
  trap 'rm -f "$tmpf"; exit' EXIT SIGINT SIGTERM

  clusterversion="$(oc get clusterversion version -o custom-columns=version:.spec.desiredUpdate.version --no-headers | perl -lne 'm,(\d+\.\d+)\.\d+, and print $1')"
  oc create job toolspod --image-registry=registry.redhat.io/openshift4/ose-tools-rhel9:v"$clusterminorversion" \
     --dry-run=client -o yaml -- sleep 18000 | tee "$tmpf"

  echo ""
  oc project
  echo ""
  if yesno "Create job"; then
    echo ""
    oc create -f "$tmpf" || die "Error creating job"

    echo "waiting for pod to be ready"
    oc wait --for=condition=ready pod -l job-name=toolspod

    echo "To enter: "
    echo "oc exec -ti job/toolspod -- /bin/bash"
    echo ""
    echo "To remove:"
    echo "oc delete job toolspod"
  else
    die "Aborted."
  fi
}

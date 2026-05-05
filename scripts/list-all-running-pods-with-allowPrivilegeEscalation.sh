#!/bin/bash
#
# Report pods with allowPrivilegeEscalation == TRUE for every container in every running pod.
# cato@x13.no
#

###
die() {
  echo "Died: $*"
  exit 1
}

#
# MAIN
#
{
  oc whoami &>/dev/null || die "Not logged in"
  set -uo pipefail

  export tempfile=/tmp/allpods.yml.gz

  if ! [ -f "$tempfile" ]; then
    ( umask 0077; oc get pods -A -o yaml | gzip > $tempfile; )
  else
    echo "Using existing file $tempfile"
  fi

  zcat $tempfile | yq -r '
    .items[] as $p |
      select($p.status.phase == "Running") |
      $p.spec.containers[] |
      [
        $p.metadata.namespace,
        $p.metadata.name,
        .name,
        ($p.metadata.annotations["openshift.io/scc"] // "<none>"),
        (.securityContext.allowPrivilegeEscalation // "<unset>")
      ] |
      select(.[4] == true) |
      @tsv
  ' | column -t -s $'\t' -N NAMESPACE,POD,CONTAINER,SCC,ALLOW_PRIV_ESC
}

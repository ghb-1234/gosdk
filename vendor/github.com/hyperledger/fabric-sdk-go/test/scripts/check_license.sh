#!/bin/bash
#
# Copyright IBM Corp, SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

function filterExcludedFiles {
  CHECK=`echo "$CHECK" | grep -v .png$ | grep -v .rst$ | grep -v ^.git/ \
  | grep -v .pem$ | grep -v .block$ | grep -v .tx$ | grep -v ^LICENSE$ | grep -v _sk$ \
  | grep -v .key$ | grep -v .crt$ | grep -v \\.gen.go$ | grep -v \\.json$ | grep -v Gopkg.lock$ \
  | grep -v .md$ | grep -v ^vendor/ | grep -v ^build/ | grep -v .pb.go$ | grep -v ci.properties$ | sort -u`
}

CHECK=$(git diff --name-only --diff-filter=ACMRTUXB HEAD)
filterExcludedFiles
if [[ -z "$CHECK" ]]; then
  LAST_COMMITS=($(git log -2 --pretty=format:"%h"))
  CHECK=$(git diff-tree --no-commit-id --name-only --diff-filter=ACMRTUXB -r ${LAST_COMMITS[1]} ${LAST_COMMITS[0]})
  filterExcludedFiles
fi

if [[ -z "$CHECK" ]]; then
   echo "All files are excluded from having license headers"
   exit 0
fi

missing=`echo "$CHECK" | xargs ls -d 2>/dev/null | xargs grep -L "SPDX-License-Identifier"`
if [[ -z "$missing" ]]; then
   echo "All files have SPDX-License-Identifier headers"
   exit 0
fi
echo "The following files are missing SPDX-License-Identifier headers:"
echo "$missing"
echo
echo "Please replace the Apache license header comment text with:"
echo "SPDX-License-Identifier: Apache-2.0"

echo
echo "Checking committed files for traditional Apache License headers ..."
missing=`echo "$missing" | xargs ls -d 2>/dev/null | xargs grep -L "http://www.apache.org/licenses/LICENSE-2.0"`
if [[ -z "$missing" ]]; then
   echo "All remaining files have Apache 2.0 headers"
   exit 0
fi
echo "The following files are missing traditional Apache 2.0 headers:"
echo "$missing"
echo "Fatal Error - All files must have a license header"
exit 1

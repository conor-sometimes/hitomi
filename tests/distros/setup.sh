#!/usr/bin/env bash
# Unpack hitomi's rules and the EICAR accuracy suite the matrix staged as tars.
set -euo pipefail
mkdir -p /etc/hitomi/rules /opt/suite
tar -C /etc/hitomi/rules --strip-components=1 -xf /opt/hitomi/rules.tar
tar -C /opt/suite        --strip-components=1 -xf /opt/hitomi/suite.tar

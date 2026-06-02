#!/usr/bin/env bash
# To download this script run from root: sudo curl https://raw.githubusercontent.com/boconnor2017/hesiod-theogony/refs/heads/main/ubuntu/refresh-ubuntu.sh >> refresh-ubuntu.sh
set -e
rm -r /usr/local/hesiod-theogony
git clone https://github.com/boconnor2017/hesiod-theogony.git /usr/local/hesiod-theogony
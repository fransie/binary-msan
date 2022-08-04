#!/bin/bash

# init env vars
current=$PWD
cd ${ZIPR_PATH}
source set_env_vars
cd $current
export PSPATH=$PSPATH:$BINMSAN_HOME/plugins_install
export CAPSTONE=${PEASOUP_HOME}/irdb-libs/third_party/capstone/include/capstone
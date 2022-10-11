#!/bin/bash


#Usage: ./counter.sh <BINARY> <OUTPUT_FILE_NAME>"

# init env vars
current=$PWD
cd ${ZIPR_PATH}
source set_env_vars
cd $current
export PSPATH=$PSPATH:$BINMSAN_HOME/plugins_install
export CAPSTONE=${PEASOUP_HOME}/irdb-libs/third_party/capstone/include/capstone

$PSZ -c rida --step move_globals -c counter --step-option $2 $1 $1_san
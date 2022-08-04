#!/bin/bash

printUsage(){
	echo "Usage: $0 <OPTIONS> <INPUT_BINARY> <OUTPUT_BINARY>"
}

printOptions(){
  echo "Options:"
  echo "-?                           Display this help screen."
  echo "-h                           Display this help screen."
  echo "-k                           Keep going after MSan warning."
  echo "-l                           Enable debug logging to stdout."
}

show_help(){
  printUsage
  echo ""
  printOptions
  exit 0
}

# init env vars
current=$PWD
cd ${ZIPR_PATH}
source set_env_vars
cd $current
export PSPATH=$PSPATH:$BINMSAN_HOME/plugins_install
export CAPSTONE=${PEASOUP_HOME}/irdb-libs/third_party/capstone/include/capstone


# https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
OPTIND=1         # Reset in case getopts has been used previously in the shell.
keep_going=""
log=""

while getopts "h?kl" opt; do
  case "$opt" in
    h|\?)
      show_help
      exit 0
      ;;
    k)
      keep_going="-k"
      ;;
    l)
      log="-l"
      ;;
  esac
done

shift $((OPTIND-1))
[ "${1:-}" = "--" ] && shift

if [ "$#" -lt 2 ]
then
  echo "Not enough arguments."
	printUsage
	exit 2
fi

options=""
if [ ! -z "${keep_going}" ]
then
  options+="--step-option ${keep_going} "
fi

if [ ! -z "${log}" ]
then
  options+="--step-option ${log} "
fi

command="$PSZ -c rida --step move_globals -c binmsan $options $1 $2"
$command
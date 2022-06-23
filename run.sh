#!/bin/bash

printUsage(){
	echo "Usage: $0 <OPTIONS> <INPUT_BINARY> <OUTPUT_BINARY>"
}

printOptions(){
  echo "Options:"
  echo "-?                           Display this help screen."
  echo "-h                           Display this help screen."
  echo "-k                           Keep going after MSan warning."
}

show_help(){
  printUsage
  echo ""
  printOptions
  exit 0
}

# https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
OPTIND=1         # Reset in case getopts has been used previously in the shell.
halt_on_error=""

while getopts "h?k" opt; do
  case "$opt" in
    h|\?)
      show_help
      exit 0
      ;;
    k)
      halt_on_error="-k"
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

if [ ! -z "${halt_on_error}" ]
then
  options="--step-option ${halt_on_error}"
fi

command="$PSZ -c rida --step move_globals -c binmsan $options $1 $2"
$command
#!/bin/bash

# build
fileName=$1
testname=${fileName%.*}
outputName=obj/${testname}
mkdir -p obj
CXX=g++-9 g++ "${fileName}" -o "$outputName"

# sanitize
mkdir -p logs
sanName="${outputName}_sanitized"
$PSZ -c rida --step move_globals -c binmsan "$outputName" "$sanName" > "logs/${testname}.txt" 2>&1

# run
./"$sanName" >> "logs/${testname}.txt"
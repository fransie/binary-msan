#!/bin/bash

# verify test not disabled
fileName=$1
disabled=$( grep -c "DISABLED" $fileName )
if [ $disabled = 1 ]
  then
    echo "Test disabled."
    exit 2
fi

# build
testname=${fileName%.*}
outputName=obj/${testname}
mkdir -p obj
CXX=g++-9 g++ "${fileName}" -o "$outputName"

# sanitize
mkdir -p logs
sanName="${outputName}_sanitized"
$PSZ -c rida --step move_globals -c binmsan "$outputName" "$sanName" > "logs/${testname}.txt" 2>&1

# run
./"$sanName" >> "logs/${testname}.txt" 2>&1
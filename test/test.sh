#!/bin/bash

# remove artifacts from last run
rm logs/*
rm obj/*

# build
fileName=$1
testname=${fileName%.*}
outputName=obj/${testname}
mkdir -p obj
CXX=g++-9 g++ "${fileName}" -o "$outputName"

# sanitize
sanName="${outputName}_sanitized"
$PSZ -c rida --step move_globals -c binmsan "$outputName" "$sanName" >/dev/null 2>&1

# run and log
mkdir -p logs
./"$sanName" > "logs/${testname}.txt"
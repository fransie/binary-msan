#!/bin/bash

# create dirs
mkdir -p obj
mkdir -p logs

# remove artifacts from last test run
rm obj/* > /dev/null 2>&1
rm logs/* > /dev/null 2>&1
rm -r peasoup_executable_directory* > /dev/null 2>&1
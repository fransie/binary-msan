#!/bin/bash

for dir in MovHandlerTests . BasicInstructionHandlerTests
do
  # create dirs
  mkdir -p "$dir"/obj
  mkdir -p "$dir"/logs

  # remove artifacts from last test run
  rm "$dir"/obj/* > /dev/null 2>&1
  rm "$dir"/logs/* > /dev/null 2>&1
  rm -r "$dir"/peasoup_executable_directory* > /dev/null 2>&1
done
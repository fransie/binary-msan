//
// Created by Franziska Mäckel on 01.07.22.
//

#include "CompareHandler.h"

void CompareHandler::instrument(IRDB_SDK::Instruction_t *instruction) {

}

const std::vector<std::string> &CompareHandler::getAssociatedInstructions() {
    return associatedInstructions;
}

CompareHandler::CompareHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr){}

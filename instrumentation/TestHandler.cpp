//
// Created by Franziska Mäckel on 05.06.22.
//

#include "TestHandler.h"

void TestHandler::instrument(IRDB_SDK::Instruction_t *instruction) {

}

const std::string &TestHandler::getAssociatedInstruction() {
    return associatedInstruction;
}

TestHandler::TestHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr) {

}


#include <iostream>
#include <irdb-core>
#include "MSan.h"


int main(int argc, char *argv[]) {

    const std::string program_name = std::string(argv[0]);
    const auto variantID = std::strtol(argv[1], nullptr, 10);

    // stand-alone transforms must setup the interface to the sql server
    auto pqxx_interface = IRDB_SDK::pqxxDB_t::factory();
    IRDB_SDK::BaseObj_t::setInterface(pqxx_interface.get());

    // stand-alone transforms must create and read a variant ID from the database
    auto pidp = IRDB_SDK::VariantID_t::factory((int) variantID);
    assert(pidp->isRegistered() == true);

    // stand-alone transforms must create and read the main file's IR from the database
    auto this_file = pidp->getMainFile();
    auto url = this_file->getURL();

    bool success = false;

    try {
        // Create and download the file's IR.
        auto firp = IRDB_SDK::FileIR_t::factory(pidp.get(), this_file);
        assert(firp && pidp);
        std::cout << "Transforming " << this_file->getURL() << std::endl;

        MSan msan(firp.get());
        success = msan.parseArgs(argc, argv);
        if (success) {
            success = msan.executeStep();
        }

        if (success) {
            std::cout << "Writing changes for " << url << std::endl;

            // Stand alone transforms must manually write the IR back to the IRDB and commit the transaction to postgres
            firp->writeToDB();
            pqxx_interface->commit();
        } else {
            std::cout << "Skipping write back on failure. " << url << std::endl;
        }
    } catch (const IRDB_SDK::DatabaseError_t &db_error) {
        std::cout << program_name << ": Unexpected database error: " << db_error << "file url: " << url << std::endl;
    } catch (...) {
        std::cout << program_name << ": Unexpected error file url: " << url << std::endl;
        return 2;
    }

    return success ? 0 : 2;
}
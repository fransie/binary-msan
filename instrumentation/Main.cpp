
#include <iostream>
#include <irdb-core>
#include "MSan.h"


int main(int argc, char* argv[]) {

    const std::string program_name = std::string(argv[0]);
    const auto variantID = std::strtol(argv[1], nullptr, 10);

    // stand-alone transforms must setup the interface to the sql server
    auto pqxx_interface = IRDB_SDK::pqxxDB_t::factory();
    IRDB_SDK::BaseObj_t::setInterface(pqxx_interface.get());

    // stand-alone transforms must create and read a variant ID from the database
    auto pidp = IRDB_SDK::VariantID_t::factory((int)variantID);
    assert(pidp->isRegistered()==true);

    // stand-alone transforms must create and read the main file's IR from the database
    auto this_file = pidp->getMainFile();
    auto url = this_file->getURL();

    // declare for later so we can return the right value
    bool success = false;

    // now try to load the IR and execute a transform
    try {
        // Create and download the file's IR.
        // Note:  this is achieved differently with thanos-enabled plugins
        auto firp = IRDB_SDK::FileIR_t::factory(pidp.get(), this_file);

        // sanity
        assert(firp && pidp);

        // log
        std::cout << "Transforming " << this_file->getURL() << std::endl;

        // create and invoke the transform
        MSan msan(firp.get());
        success = msan.parseArgs(argc, argv);
        if (success) {
            success = msan.executeStep();
        }

        // conditionally write the IR back to the database on success
        if (success) {
            std::cout << "Writing changes for " << url << std::endl;

            // Stand alone transforms must manually write the IR back to the IRDB
            firp->writeToDB();

            // and commit the transaction to postgres
            pqxx_interface->commit();
        } else {
            std::cout << "Skipping write back on failure. " << url << std::endl;
        }
    } catch (const IRDB_SDK::DatabaseError_t &db_error) {
        std::cout << program_name << ": Unexpected database error: " << db_error << "file url: " << url << std::endl;
    } catch (...) {
        std::cout<< program_name << ": Unexpected error file url: " << url << std::endl;
        return 2;
    }

    return success ? 0 : 2;
}
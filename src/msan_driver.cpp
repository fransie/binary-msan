//
// Created by Franziska Mäckel on 03.04.22.
//

#include <fstream>
#include <irdb-core>
#include "msan.hpp"

using namespace std;
using namespace IRDB_SDK;

//
// Thanos-enabled transform. Thanos-enabled transforms must implement the TransfromStep_t abstract class.
// See the IRDB SDK for additional details.
//
class MSanDriver_t : public IRDB_SDK::TransformStep_t
{
public:
    //
    // required override: how to parse your options
    //
    int parseArgs(const vector<string> step_args) override
    {
        // no arguments to parse.
        return 0; // success (bash-style 0=success, 1=warnings, 2=errors)
    }

    //
    // required override: how to achieve the actual transform
    //
    int executeStep() override
    {
        // record the URL from the main file for log output later
        auto url=getMainFile()->getURL();

        // try to load and transform the file's IR.
        try
        {
            // load the fileIR (or, get the handle to an already loaded IR)
            auto firp = getMainFileIR();

            // create a transform object and execute a transform
            auto success = MSan(firp).execute(firp);

            // check for success
            if (success)
            {
                cout << "Success! Thanos will write back changes for " <<  url << endl;
                return 0; // success (bash-style 0=success, 1=warnings, 2=errors)
            }

            // failure
            cout << "Failure!  Thanos will report error to user for " << url << endl;
            return 2; // error
        }
        catch (const DatabaseError_t& db_err)
        {
            cerr << program_name << ": Unexpected database error: " << db_err << "file url: " << url << endl;
            return 2; // error
        }
        catch (...)
        {
            cerr << program_name << ": Unexpected error file url: " << url << endl;
            return 2; // error
        }
        assert(0); // unreachable
    }

    //
    // required override:  report the step name
    //
    string getStepName(void) const override
    {
        return program_name;
    }

private:
    // data
    const string program_name = string("msan");

    // methods

    //
    // optional:  print using info for this transform.
    // This transform takes no parameters.
    //
    void usage(const string& p_name)
    {
        cerr << "Usage: " << p_name << endl;
    }
};


//
// Required interface: a factory for creating the interface object for this transform.
//
extern "C"
shared_ptr<TransformStep_t> getTransformStep(void)
{
    return shared_ptr<TransformStep_t>(new MSanDriver_t());
}

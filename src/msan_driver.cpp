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
class MSanDriver_t : public IRDB_SDK::Transform_t
{
public:
    MSanDriver_t(IRDB_SDK::FileIR_t *file) :
    Transform_t(file){

    }

    //
    // required override: how to parse your options
    //
    int parseArgs(const vector<string> step_args)
    {
        // no arguments to parse.
        return 0; // success (bash-style 0=success, 1=warnings, 2=errors)
    }

    //
    // required override: how to achieve the actual transform
    //
    int executeStep()
    {
        cout << "start of executeStep in msan_driver";
        // try to load and transform the file's IR.
        try
        {
            // load the fileIR (or, get the handle to an already loaded IR)
            auto firp = getFileIR();

            // create a transform object and execute a transform
            //auto success = MSan(firp).execute();
            auto success = true;
            // check for success
            if (success)
            {
                cout << "Success!" << endl;
                return 0; // success (bash-style 0=success, 1=warnings, 2=errors)
            }

            // failure
            cout << "Failure!" << endl;
            return 2; // error
        }
        catch (const DatabaseError_t& db_err)
        {
            cerr << program_name << ": Unexpected database error: " << db_err << endl;
            return 2; // error
        }
        catch (...)
        {
            cerr << program_name << endl;
            return 2; // error
        }
        assert(0); // unreachable
    }

    //
    // required override:  report the step name
    //
    string getStepName(void) const
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

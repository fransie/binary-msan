#ifndef JUMPS_PASS_H
#define JUMPS_PASS_H

#include <irdb-core>
#include <irdb-transform>
#include <irdb-deep>
#include "eflags_access.hpp"

/**
 * Finds conditional jumps and instruments them to check whether they branch based
 * on uninitialised memory, possibly leading to an error. It's a TransformStep used by Thanos.
 */
class JumpsPass : public IRDB_SDK::TransformStep_t {
	public:
        ~JumpsPass() override= default;

        std::string getStepName() const override;
        int parseArgs(std::vector<std::string> step_args) override;
        int executeStep() override;
        void insertEFlagsCheckInstrumentation(const std::vector<Eflags::Flag>& flags, IRDB_SDK::Instruction_t* instruction, IRDB_SDK::FileIR_t* fileIR) const;

	private:
		void registerDependencies();

        //IRDB_SDK::Instruction_t* msan_init;
        const int64_t eflagShadowOffset = 0x1000;
};

/**
 * Required interface for thanos: a factory for creating the interface object for this transform.
 */
extern "C" std::shared_ptr<IRDB_SDK::TransformStep_t> getTransformStep(void)
{
	return std::shared_ptr<IRDB_SDK::TransformStep_t>(new JumpsPass());
}

#endif

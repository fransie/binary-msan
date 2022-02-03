#ifndef JUMPS_PASS_H
#define JUMPS_PASS_H

#include <irdb-core>
#include <irdb-transform>
#include <irdb-deep>

/**
 * Finds conditional jumps and instruments them to check whether they branch based
 * on uninitialised memory, possibly leading to an error. It's a TransformStep used by Thanos.
 */
class JumpsPass : public IRDB_SDK::TransformStep_t {
	public:
        ~JumpsPass(void){};

        std::string getStepName(void) const override;
        int parseArgs(const std::vector<std::string> step_args) override;
        int executeStep() override;

	private:
		void registerDependencies();
};

/**
 * Required interface for thanos: a factory for creating the interface object for this transform.
 */
extern "C" std::shared_ptr<IRDB_SDK::TransformStep_t> getTransformStep(void)
{
	return std::shared_ptr<IRDB_SDK::TransformStep_t>(new JumpsPass());
}

#endif

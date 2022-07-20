#include <iostream>
#include <memory>
#include <msan_interface_internal.h>
#include "../common/Width.h"
#include "../common/RegisterNumbering.h"
#include "Interface.h"

// TODO: global variable is probably a bad idea
/**
 * This vector holds the current shadow state of the 16 general purpose registers. Upon initialisation,
 * each bit of all of them has the state "undefined" (1). Registers numbering: see file operand_csx86.cpp in zipr.
 */
std::vector<std::bitset<64>> shadowRegisterState = std::vector<std::bitset<64>>(16, std::bitset<64>{}.set());

/**
 * Represents the shadow of the EFLAGS register in one bit. Hence, this is only an approximation.
 */
bool eflagsDefined = true;

/**
 * Takes two ints representing general purpose registers and propagates the shadow value of the
 * source register to the destination register.
 *
 * This method assumes that destWidth and srcWidth are the same. Only exception: BYTE and HIGHER_BYTE can
 * be mixed.
 *
 * @param dest the number of the destination register
 * @param destWidth the width of the dest register in bits. "0" denominates the second-least significant byte.
 * @param src the number of the source register
 * @param srcWidth the width of the source registers in bits. "0" denominates the second-least significant byte.
 */
void regToRegShadowCopy(const int dest, int destWidth, const int src, const int srcWidth) {
    std::cout << "regToRegShadowCopy. Dest value: " << dest << ". Source value: " << src << ". Width: " << srcWidth;
    int positionDest = 0;
    int positionSrc = 0;
    if(destWidth == HIGHER_BYTE || srcWidth == HIGHER_BYTE){
       if (destWidth == HIGHER_BYTE){
           positionDest = 8;
           destWidth = 16;
       }
        if (srcWidth == HIGHER_BYTE){
            positionSrc = 8;
        }
    }
    while(positionDest < destWidth){
        shadowRegisterState[dest].set(positionDest, shadowRegisterState[src][positionSrc]);
        positionDest++;
        positionSrc++;
    }
    std::cout << ". New dest shadow: " << shadowRegisterState[dest].to_ullong() << std::endl;
}

/**
 * Checks whether the first regWidth bits of the register referenced by <code>reg</code> are initialised. If not,
 * an MSan Warning is issued.
 * Special case: If regWidth is HIGHER_BYTE (e.g. AH), then the bits at position 8 - 15 are checked.
 * @param reg number of the register to be checked.
 * @param regWidth width of the register in bits.
 */
void checkRegIsInit(int reg, int regWidth) {
    std::cout << "checkRegIsInit. Register: " << reg << ". Width: " << regWidth << ". Register shadow: 0x" << std::hex << shadowRegisterState[reg].to_ullong() << std::endl;
    if(shadowRegisterState[reg].any()){
        int bit = 0;
        if(regWidth == HIGHER_BYTE){
            bit = 8;
            regWidth = 16;
        }
        for (; bit < regWidth; bit++){
            if(shadowRegisterState[reg].test(bit) == 1){
                __msan_warning();
                break;
            }
        }
    }
}

/**
 * Copies the shadow associated with <code>memAddress</code> into the shadow state of the register <code>reg</code>.
 *
 * @param reg Number of the destination register.
 * @param regWidth Width of the destination register.
 * @param memAddress Source memory address.
 */
void memToRegShadowCopy(int reg, int regWidth, uptr memAddress){
    std::cout << "memToRegShadowCopy. Register: " << reg << ". RegWidth: " << regWidth << ". MemAddress: 0x" << std::hex << memAddress << "." << std::endl;
    if (!MEM_IS_APP(memAddress)) {
        std::cout << memAddress << " is not an application address." << std::endl;
        return;
    }
    // char pointers in C++ can read memory byte by byte
    auto memShadowAddress = reinterpret_cast<char*>(MEM_TO_SHADOW(memAddress));
    int position = 0;
    if(regWidth == HIGHER_BYTE){
        regWidth = 8;
        position = 8;
    }
    for (int byte = 0; byte < (regWidth / BYTE); byte++){
        char bits = *memShadowAddress;
        for (int x = 0; x < 8; x++){
            auto bit = (bits >> x) & 1U;
            shadowRegisterState[reg].set(position, bit);
            position++;
        }
        memShadowAddress++;
    }
    std::cout << "memToRegShadowCopy. Shadow of reg " << reg << " is: 0x" << std::hex << shadowRegisterState[reg].to_ullong() << "." << std::endl;
}

/**
 * Verifies whether the EFLAGS register is initialised and if not, causes an msan warning.
 */
void checkEflags() {
    if(!eflagsDefined){
        __msan_warning();
    }
}

/**
 * Set the shadow of the EFLAGS register where shadow = 1 or true means undefined.
 */
void setEflags(bool shadow) {
    std::cout << "setEflags to " << shadow << std::endl;
    eflagsDefined = shadow;
}

/**
 * Unpoisons RBP and RSP.
 */
void initGpRegisters() {
    std::cout << "Init rbp and rsp." << std::endl;
    shadowRegisterState[RSP].reset();
    shadowRegisterState[RBP].reset();
}

/**
 * Propagates the shadow associated with the register <code>reg</code> to <code>memAddress</code>.
 * @param reg
 * @param regWidth
 * @param memAddress
 */
void regToMemShadowCopy(int reg, int regWidth, uptr memAddress) {
    std::cout << "regToMemShadowCopy. Register: " << reg << ". RegWidth: " << regWidth << ". MemAddress: 0x" << std::hex << memAddress << std::endl;
    int size = regWidth / BYTE;
    if(regWidth == HIGHER_BYTE){
        size = 1;
    }
    auto shadow = getRegisterShadow(reg, regWidth);
    __msan_partial_poison(reinterpret_cast<const void *>(memAddress), shadow, size);
}

/**
 * Gets the shadow of register <code>reg</code> based on <code>regWidth<code>. Since the width can differ,
 * this functions returns a void pointer. To use the shadow, cast it to an appropriate pointer according to its width.
 * For example, if you input regWidth = 16, then cast the returned void pointer to uint_16t pointer.
 * @param reg register.
 * @param regWidth register width in bits.
 * @return pointer to register shadow cast to void*.
 */
void *getRegisterShadow(int reg, int regWidth) {
    auto shadowValue = shadowRegisterState[reg].to_ullong();
    switch (regWidth) {
        case QUAD_WORD:{
            auto *shadow_ptr = new uint64_t;
            *shadow_ptr = shadowValue;
            return reinterpret_cast<void *>(shadow_ptr);
        }
        case DOUBLE_WORD:{
            auto *shadow_ptr = new uint32_t;
            *shadow_ptr = static_cast<uint32_t>(shadowValue);
            return reinterpret_cast<void *>(shadow_ptr);
        }
        case WORD: {
            auto *shadow_ptr = new uint16_t;
            *shadow_ptr = static_cast<uint16_t>(shadowValue);
            return reinterpret_cast<void *>(shadow_ptr);
        }
        case HIGHER_BYTE:{
            auto *shadow_ptr = new uint8_t;
            shadowValue = shadowValue >> 8;
            *shadow_ptr = static_cast<uint8_t>(shadowValue);
            return reinterpret_cast<void *>(shadow_ptr);
        }
        case BYTE: {
            auto *shadow_ptr = new uint8_t;
            *shadow_ptr = static_cast<uint8_t>(shadowValue);
            return reinterpret_cast<void *>(shadow_ptr);
        }
        default:
            throw std::invalid_argument("Function regToRegShadowCopy was called with an unsupported width value.");
    }
}

/**
 * Returns true if the input register <code>reg</code> is fully defined in the bits denoted by <code>width</code>.
 */
bool isRegFullyDefined(int reg, int width) {
    if (shadowRegisterState[reg].none()){
        return true;
    } else {
        int startFrom = 0;
        if(width == HIGHER_BYTE){
            startFrom = 8;
            width = 8;
        }
        for (int position = startFrom; position < (startFrom + width); position++){
            if(shadowRegisterState[reg].test(startFrom) == 1){
                return false;
            }
        }
        return true;
    }
}

/**
 * Returns true if the input memory location starting at <code>mem</code> of size <code>size</code> is fully defined.
 */
bool isMemFullyDefined(const void *mem, uptr size) {
    auto firstUninitByte = __msan_test_shadow(mem, size);
    return (firstUninitByte == -1);
}

/**
 * Returns true if both input registers are fully initialised.
 */
bool isRegOrRegFullyDefined(int dest, int destWidth, int src, int srcWidth) {
    if(destWidth == HIGHER_BYTE || srcWidth == HIGHER_BYTE){
        int destBit = 0;
        if(destWidth == HIGHER_BYTE){
            destBit = 8;
            destWidth = 16;
        }
        for (; destBit < destWidth; destBit++){
            if(shadowRegisterState[dest].test(destBit) == 1){
                return false;
            }
        }
        int srcBit = 0;
        if(srcWidth == HIGHER_BYTE){
            srcBit = 8;
            srcWidth = 16;
        }
        for (; srcBit < srcWidth; srcBit++){
            if(shadowRegisterState[src].test(srcBit) == 1){
                return false;
            }
        }
        return true;
    }

    auto registerOr = shadowRegisterState[dest] | shadowRegisterState[src];
    if(registerOr.none()){
        return true;
    } else {
        for (int bit = 0; bit < destWidth; bit++){
            if(registerOr.test(bit) == 1){
                return false;
            }
        }
        return true;
    }
}

// TODO: decide to either take bits everywhere or bytes! Or make clear which function
// takes width in bytes and which in bits
/**
 * Returns true if both the input register and the input memory location are fully initialised.
 */
bool isRegOrMemFullyDefined(int reg, const void *mem, int width) {
    sptr firstUninitByte;
    if(width == HIGHER_BYTE){
        firstUninitByte = __msan_test_shadow(mem, 1);
    } else{
        firstUninitByte = __msan_test_shadow(mem, width / BYTE);
    }
    if (firstUninitByte != -1){
        return false;
    }
    return isRegFullyDefined(reg, width);
}

void setRegShadow(bool isInited, int reg, int width) {
    auto shadowValue = !isInited;
    int startFrom = 0;
    if(width == HIGHER_BYTE){
        startFrom = 8;
        width = 8;
    }
    for(int position = startFrom; position < (startFrom + width); position++){
        shadowRegisterState[reg].set(position, shadowValue);
    }
}

/**
 * Sets the shadow of the memory location denoted by <code>mem</code> and <code>size</code>.
 * @param isInited isInited = true -> unpoison memory, isInited = false -> poison memory.
 */
void setMemShadow(bool isInited, const void *mem, uptr size) {
    if(isInited){
        __msan_unpoison(mem, size);
    } else {
        __msan_poison(mem, size);
    }
}

/**
 * Unpoison the four higher bytes of <code>reg</code>.
 */
void initUpper4Bytes(const int reg) {
    shadowRegisterState[reg] = shadowRegisterState[reg] & std::bitset<64>{0x00000000ffffffff};
}

void propagateRegOrRegShadow(int dest, int destWidth, int src, int srcWidth) {
    auto destShadow = getRegisterShadow(dest, destWidth);
    auto srcShadow = getRegisterShadow(src, srcWidth);
    uint64_t newDestShadow = 0;
    uint64_t operationShadow = 0;
    switch (destWidth) {
        case QUAD_WORD:
            newDestShadow = *((uint64_t*)destShadow) | *((uint64_t*)srcShadow);
            break;
        case DOUBLE_WORD:
            newDestShadow = *((uint32_t*)destShadow) | *((uint32_t*)srcShadow);
            // Higher four bytes are zeroed in double word operations.
            newDestShadow = newDestShadow & 0x00000000ffffffff;
            break;
        case WORD:
            // preserve shadow of higher 6 bytes of dest
            operationShadow = *((uint16_t*)destShadow) | *((uint16_t*)srcShadow);
            newDestShadow = shadowRegisterState[dest].to_ullong() | operationShadow;
            break;
        case BYTE:
            // preserve shadow of higher 6 bytes of dest
            operationShadow = *((uint8_t*)destShadow) | *((uint8_t*)srcShadow);
            newDestShadow = shadowRegisterState[dest].to_ullong() | operationShadow;
            break;
        case HIGHER_BYTE:
            // preserve shadow of higher 6 bytes of dest
            operationShadow = *((uint8_t*)destShadow) | *((uint8_t*)srcShadow);
            operationShadow = operationShadow << BYTE;
            newDestShadow = shadowRegisterState[dest].to_ullong() | operationShadow;
            break;
    }
    shadowRegisterState[dest] = std::bitset<64>{newDestShadow};
    eflagsDefined = newDestShadow == 0;
}

void propagateRegOrMemShadow(int reg, const void *mem, int width) {
    auto destShadow = getRegisterShadow(reg, width);
    auto srcShadow = reinterpret_cast<char*>(MEM_TO_SHADOW(mem));
    uint64_t newDestShadow = 0;
    uint64_t operationShadow = 0;
    switch (width) {
        case QUAD_WORD:
            newDestShadow = *((uint64_t*)destShadow) | *((uint64_t*)srcShadow);
            break;
        case DOUBLE_WORD:
            newDestShadow = *((uint32_t*)destShadow) | *((uint32_t*)srcShadow);
            // Higher four bytes are zeroed in double word operations.
            newDestShadow = newDestShadow & 0x00000000ffffffff;
            break;
        case WORD:
            // preserve shadow of higher 6 bytes of dest
            operationShadow = *((uint16_t*)destShadow) | *((uint16_t*)srcShadow);
            newDestShadow = shadowRegisterState[reg].to_ullong() | operationShadow;
            break;
        case BYTE:
            // preserve shadow of higher 7 bytes of dest
            operationShadow = *((uint8_t*)destShadow) | *((uint8_t*)srcShadow);
            newDestShadow = shadowRegisterState[reg].to_ullong() | operationShadow;
            break;
        case HIGHER_BYTE:
            // preserve shadow of higher 6 bytes and lower byte of dest
            operationShadow = *((uint8_t*)destShadow) | *((uint8_t*)srcShadow);
            operationShadow = operationShadow << BYTE;
            newDestShadow = shadowRegisterState[reg].to_ullong() | operationShadow;
            break;
    }
    shadowRegisterState[reg] = std::bitset<64>{newDestShadow};
    eflagsDefined = newDestShadow == 0;
}

void propagateMemOrRegShadow(int reg, const void *mem, int width) {
    auto destShadow = reinterpret_cast<char*>(MEM_TO_SHADOW(mem));
    auto srcShadow = getRegisterShadow(reg, width);
    uint64_t* newDestShadow = new uint64_t;
    switch (width) {
        case QUAD_WORD:
            *newDestShadow = *((uint64_t*)destShadow) | *((uint64_t*)srcShadow);
            break;
        case DOUBLE_WORD:
            *newDestShadow = *((uint32_t*)destShadow) | *((uint32_t*)srcShadow);
            break;
        case WORD:
            *newDestShadow = *((uint16_t*)destShadow) | *((uint16_t*)srcShadow);
            break;
        case BYTE:
        case HIGHER_BYTE:
            *newDestShadow = *((uint8_t*)destShadow) | *((uint8_t*)srcShadow);
            break;
        default:
            throw std::invalid_argument("propagateMemOrRegShadow was called with an invalid width argument.");
    }
    if (width == HIGHER_BYTE){
        width = BYTE;
    }
    __msan_partial_poison(mem, (void*)newDestShadow, width / BYTE);
    eflagsDefined = *newDestShadow == 0;
}

import os
from pprint import pprint

if __name__ == '__main__':

    print("Extracting used cpp files...")
    msan_path = "/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/"
    store_path = "/home/franzi/Documents/sync/"
    os.system(f"ar -t {msan_path}libclang_rt.msan_cxx-x86_64.a > {store_path}objectfiles_cxx")
    os.system(f"ar -t {msan_path}libclang_rt.msan-x86_64.a > {store_path}objectfiles_c")

    with open('/home/franzi/Documents/sync/objectfiles_cxx') as f:
        lines = f.readlines()

    cppfiles = []
    path_to_lib = "/home/franzi/Documents/llvm-project/compiler-rt/lib/"
    for line in lines:
        if "ubsan" in line:
            stripped = line.strip(".o\n")
            cppfiles.append(path_to_lib + "ubsan/" + stripped)
        if "msan" in line:
            stripped = line.strip(".o\n")
            cppfiles.append(path_to_lib + "msan/" + stripped)
        if "sanitizer" in line or "sancov" in line:
            stripped = line.strip(".o\n")
            cppfiles.append(path_to_lib + "sanitizer_common/" + stripped)
        if "interception" in line:
            stripped = line.strip(".o\n")
            cppfiles.append(path_to_lib + "interception/" + stripped)

    with open('/home/franzi/Documents/sync/objectfiles_c') as f:
        lines = f.readlines()

    cfiles = []
    for line in lines:
        if "ubsan" in line:
            stripped = line.strip(".o\n")
            cfiles.append(path_to_lib + "ubsan/" + stripped)
        if "msan" in line:
            stripped = line.strip(".o\n")
            cfiles.append(path_to_lib + "msan/" + stripped)
        if "sanitizer" in line or "sancov" in line:
            stripped = line.strip(".o\n")
            cfiles.append(path_to_lib + "sanitizer_common/" + stripped)
        if "interception" in line:
            stripped = line.strip(".o\n")
            cfiles.append(path_to_lib + "interception/" + stripped)

    # build object files from source files
    # print("Building object files...")
    # for file in cppfiles:
    #     os.system(f"g++ -std=c++17 -fPIC -c {file} -I{path_to_lib}")
    # for file in cfiles:
    #     os.system(f"g++ -std=c++17 -fPIC -c {file} -I{path_to_lib}")

    ofiles_cxx = ""
    ofiles_c = ""

    for file in cfiles:
        ofiles_c += (file.replace(".cpp","").split("/")[-1] + ".o ")
    for file in cppfiles:
        ofiles_cxx += (file.replace(".cpp","").split("/")[-1] + ".o ")
    print("Files that will be included in libmsan_c:")
    pprint(ofiles_c)
    print("Files that will be included in libmsan_cxx:")
    pprint(ofiles_cxx)

    # build c++ shared library
    print("Building cxx shared object...")
    os.system(f"gcc -shared -o libmsan_cxx.so {ofiles_cxx}")

    # build c shared library
    print("Building c shared object...")
    os.system(f"gcc -shared -o libmsan_c.so {ofiles_c}")

import os
from pprint import pprint

def prepend_path_to_files(included_objectfiles_file):
    with open(included_objectfiles_file) as f:
        lines = f.readlines()

    source_files = []
    for line in lines:
        if "ubsan" in line:
            filename = line.strip(".o\n")
            source_files.append(path_to_msan_sourcefiles + "ubsan/" + filename)
        if "msan" in line:
            filename = line.strip(".o\n")
            source_files.append(path_to_msan_sourcefiles + "msan/" + filename)
        if "sanitizer" in line or "sancov" in line:
            filename = line.strip(".o\n")
            source_files.append(path_to_msan_sourcefiles + "sanitizer_common/" + filename)
        if "interception" in line:
            filename = line.strip(".o\n")
            source_files.append(path_to_msan_sourcefiles + "interception/" + filename)
    return source_files


if __name__ == '__main__':

    print("Extracting used cpp files...")
    path_to_static_libraries = "/usr/lib/llvm-14/lib/clang/14.0.0/lib/linux/"
    store_path = "/home/franzi/Documents/sync/"
    # ar -t prints all object files included in a static libary
    os.system(f"ar -t {path_to_static_libraries}libclang_rt.msan_cxx-x86_64.a > {store_path}objectfiles_cxx")
    os.system(f"ar -t {path_to_static_libraries}libclang_rt.msan-x86_64.a > {store_path}objectfiles_c")

    # read object file names, get the source file names and prepend the path to the source file name
    path_to_msan_sourcefiles = "/home/franzi/Documents/llvm-project/compiler-rt/lib/"
    cppfiles = prepend_path_to_files('/home/franzi/Documents/sync/objectfiles_cxx')
    cfiles = prepend_path_to_files('/home/franzi/Documents/sync/objectfiles_c')

    # build object files from source files
    print("Building object files...")
    for file in cppfiles:
        os.system(f"g++ -std=c++17 -fPIC -c {file} -I{path_to_msan_sourcefiles}")
    for file in cfiles:
        os.system(f"g++ -std=c++17 -fPIC -c {file} -I{path_to_msan_sourcefiles}")

    # build strings containing all the names of the object files to use it for linking later on
    object_files_c = ""
    for file in cfiles:
        object_files_c += (file.replace(".cpp", "").split("/")[-1] + ".o ")
    object_files_cxx = ""
    for file in cppfiles:
        object_files_cxx += (file.replace(".cpp", "").split("/")[-1] + ".o ")
    print("Files that will be included in libmsan_c:")
    pprint(object_files_c)
    print("Files that will be included in libmsan_cxx:")
    pprint(object_files_cxx)

    # build c shared library
    print("Building c shared object...")
    os.system(f"gcc -shared -o libmsan_c.so {object_files_c}")

    # build c++ shared library
    print("Building cxx shared object...")
    os.system(f"gcc -shared -o libmsan_cxx.so {object_files_cxx}")

    print("Finished.")

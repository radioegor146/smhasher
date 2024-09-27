# CMake generated Testfile for 
# Source directory: /mnt/d/smhasher
# Build directory: /mnt/d/smhasher
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(List "SMHasher" "--list")
set_tests_properties(List PROPERTIES  _BACKTRACE_TRIPLES "/mnt/d/smhasher/CMakeLists.txt;773;add_test;/mnt/d/smhasher/CMakeLists.txt;0;")
add_test(VerifyAll "SMHasher" "--test=VerifyAll" "--verbose")
set_tests_properties(VerifyAll PROPERTIES  _BACKTRACE_TRIPLES "/mnt/d/smhasher/CMakeLists.txt;774;add_test;/mnt/d/smhasher/CMakeLists.txt;0;")
add_test(Sanity "SMHasher" "--test=Sanity")
set_tests_properties(Sanity PROPERTIES  _BACKTRACE_TRIPLES "/mnt/d/smhasher/CMakeLists.txt;775;add_test;/mnt/d/smhasher/CMakeLists.txt;0;")
add_test(Speed "SMHasher" "--test=Speed")
set_tests_properties(Speed PROPERTIES  _BACKTRACE_TRIPLES "/mnt/d/smhasher/CMakeLists.txt;776;add_test;/mnt/d/smhasher/CMakeLists.txt;0;")
add_test(Cyclic "SMHasher" "--test=Cyclic")
set_tests_properties(Cyclic PROPERTIES  _BACKTRACE_TRIPLES "/mnt/d/smhasher/CMakeLists.txt;777;add_test;/mnt/d/smhasher/CMakeLists.txt;0;")
add_test(Zeroes "SMHasher" "--test=Zeroes")
set_tests_properties(Zeroes PROPERTIES  _BACKTRACE_TRIPLES "/mnt/d/smhasher/CMakeLists.txt;778;add_test;/mnt/d/smhasher/CMakeLists.txt;0;")
add_test(Seed "SMHasher" "--test=Seed")
set_tests_properties(Seed PROPERTIES  _BACKTRACE_TRIPLES "/mnt/d/smhasher/CMakeLists.txt;779;add_test;/mnt/d/smhasher/CMakeLists.txt;0;")

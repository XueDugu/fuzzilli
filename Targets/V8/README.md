# Target: v8

To build v8 for fuzzing:

1. Follow the instructions at https://v8.dev/docs/build
2. Run the fuzzbuild.sh script in the v8 root directory
3. out/fuzzbuild/d8 will be the JavaScript shell for the fuzzer

To run the V8-focused setup in this repository with the tuned defaults added here, use:

`./Tools/run-v8-fuzz.sh /path/to/d8 [storage-dir]`

The wrapper keeps the workflow on the V8 profile and enables the settings that are currently
the most useful for long-running V8 campaigns in this tree:

* Markov corpus scheduling
* V8 argument randomization
* Swarm testing for generator weights
* Periodic statistics export

Note that sanitizer coverage for v8 is currently not supported on macOS as it is missing from v8's custom clang toolchain.

// Copyright 2026
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Fuzzilli

// Official-repo-aligned Maglev-focused profile adapted from
// https://github.com/googleprojectzero/fuzzilli/pull/507
let maglevProfile = Profile(
    processArgs: { _ in
        [
            "--expose-gc",
            "--omit-quit",
            "--allow-natives-syntax",
            "--fuzzing",
            "--jit-fuzzing",
            "--harmony",
            "--js-staging",
            "--concurrent-maglev-max-threads=1",
            "--no-concurrent_recompilation",
        ]
    },

    processEnv: [:],

    maxExecsBeforeRespawn: 1000,

    timeout: Timeout.value(300),

    codePrefix: """
                """,

    codeSuffix: """
                """,

    ecmaVersion: ECMAScriptVersion.es6,

    startupTests: [
        ("fuzzilli('FUZZILLI_PRINT', 'test')", .shouldSucceed),
        ("fuzzilli('FUZZILLI_CRASH', 0)", .shouldCrash),
        ("fuzzilli('FUZZILLI_CRASH', 1)", .shouldCrash),
        ("fuzzilli('FUZZILLI_CRASH', 2)", .shouldCrash),
        ("fuzzilli('FUZZILLI_CRASH', 3)", .shouldCrash),
    ],

    additionalCodeGenerators: [
        (V8GcGenerator,                       10),
        (ForceMaglevCompilationGenerator,      5),
        (ForceOSRThroughLoopGenerator,         5),
    ],

    additionalProgramTemplates: WeightedList<ProgramTemplate>([
        (MapTransitionFuzzer, 1),
    ]),

    disabledCodeGenerators: [],

    disabledMutators: [],

    additionalBuiltins: [
        "gc"    : .function([.opt(gcOptions.instanceType)] => (.undefined | .jsPromise)),
        "d8"    : .jsD8,
        "Worker": .constructor([.jsAnything, .object()] => .object(withMethods: ["postMessage","getMessage"])),
    ],

    additionalObjectGroups: [jsD8, jsD8Test, jsD8FastCAPI, gcOptions],

    additionalEnumerations: [.gcTypeEnum, .gcExecutionEnum],

    optionalPostProcessor: nil
)

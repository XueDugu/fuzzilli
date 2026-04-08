// Copyright 2019 Google LLC
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

fileprivate let v8JITOracleHelpers = """
                function __fuzzilliClassOf(object) {
                    const string = Object.prototype.toString.call(object);
                    return string.substring(8, string.length - 1);
                }

                function __fuzzilliDeepObjectEquals(a, b) {
                    try {
                        const aProps = Object.keys(a).sort();
                        const bProps = Object.keys(b).sort();
                        if (!__fuzzilliDeepEquals(aProps, bProps)) {
                            return false;
                        }
                        for (let i = 0; i < aProps.length; i++) {
                            if (!__fuzzilliDeepEquals(a[aProps[i]], b[aProps[i]])) {
                                return false;
                            }
                        }
                        return true;
                    } catch (e) {
                        // The oracle should not turn proxy/generator edge cases into invalid samples.
                        return true;
                    }
                }

                function __fuzzilliDeepEquals(a, b) {
                    if (a === b) {
                        if (a === 0) {
                            return (1 / a) === (1 / b);
                        }
                        return true;
                    }
                    if (typeof a !== typeof b) {
                        return false;
                    }
                    if (typeof a === 'number') {
                        return (isNaN(a) && isNaN(b)) || (a === b);
                    }
                    if (a === null || b === null) {
                        return false;
                    }
                    if (typeof a !== 'object' && typeof a !== 'function' && typeof a !== 'symbol') {
                        return false;
                    }

                    const objectClass = __fuzzilliClassOf(a);
                    if (objectClass === 'Array') {
                        if (a.length !== b.length) {
                            return false;
                        }
                        for (let i = 0; i < a.length; i++) {
                            if (!__fuzzilliDeepEquals(a[i], b[i])) {
                                return false;
                            }
                        }
                        return true;
                    }
                    if (objectClass !== __fuzzilliClassOf(b)) {
                        return false;
                    }
                    if (objectClass === 'RegExp') {
                        return a.toString() === b.toString();
                    }
                    if (objectClass === 'Function') {
                        return true;
                    }
                    if (objectClass === 'String' || objectClass === 'Number' || objectClass === 'Boolean' || objectClass === 'Date') {
                        return a.valueOf() === b.valueOf();
                    }
                    return __fuzzilliDeepObjectEquals(a, b);
                }
                """

// Inspired by FuzzJIT (USENIX Security 2023), wrap a subset of generated programs in a small
// JIT-consistency oracle that compares the observable outputs before and after optimization.
// This allows the V8 profile to detect non-crashing JIT miscompilations instead of only crashes.
fileprivate struct V8JITOraclePostProcessor: FuzzingPostProcessor {
    private let samplingRate = 0.20
    private let maxObservedValues = 6

    func process(_ program: Program, for fuzzer: Fuzzer) -> Program {
        guard !program.isEmpty else { return program }
        guard !program.containsWasm else { return program }
        guard probability(samplingRate) else { return program }

        let b = fuzzer.makeBuilder(forMutating: program)

        let opt = b.buildPlainFunction(with: .parameters(n: 1), named: "opt") { _ in
            let visibleBefore = Set(b.visibleVariables)

            b.adopting(from: program) {
                for instr in program.code {
                    b.adopt(instr)
                }
            }

            var observedValues = b.visibleVariables.filter { !visibleBefore.contains($0) }
            observedValues = observedValues.filter {
                let type = b.type(of: $0)
                return !type.Is(.function()) && !type.Is(.constructor())
            }

            if observedValues.count > maxObservedValues {
                observedValues = Array(observedValues.suffix(maxObservedValues))
            }
            if observedValues.isEmpty {
                observedValues = [b.loadInt(0)]
            }

            let result = b.createArray(with: observedValues)
            b.doReturn(result)
        }

        let deepEquals = b.createNamedVariable("__fuzzilliDeepEquals", declarationMode: .none)
        let falseValue = b.loadBool(false)

        b.buildTryCatchFinally(tryBody: {
            let baseline = b.callFunction(opt, withArgs: [falseValue])
            let baselineAgain = b.callFunction(opt, withArgs: [falseValue])
            let isDeterministic = b.callFunction(deepEquals, withArgs: [baseline, baselineAgain])

            b.eval("%PrepareFunctionForOptimization(%@)", with: [opt])
            b.callFunction(opt, withArgs: [falseValue])
            b.callFunction(opt, withArgs: [falseValue])
            b.eval("%OptimizeFunctionOnNextCall(%@)", with: [opt])

            let optimized = b.callFunction(opt, withArgs: [falseValue])
            let matchesOptimized = b.callFunction(deepEquals, withArgs: [baseline, optimized])
            let mismatchDetected = b.compare(matchesOptimized, with: falseValue, using: .strictEqual)

            b.buildIf(isDeterministic) {
                b.buildIf(mismatchDetected) {
                    b.eval("fuzzilli('FUZZILLI_CRASH', 0)")
                }
            }
        }, catchBody: { _ in
            // Ignore oracle failures and keep the sample otherwise valid.
        })

        return b.finalize()
    }
}

let v8Profile = Profile(
    processArgs: {randomize in
      v8ProcessArgs(randomize: randomize, forSandbox: false)
    },

    // We typically fuzz without any sanitizer instrumentation, but if any sanitizers are active, "abort_on_error=1" must probably be set so that sanitizer errors can be detected.
    processEnv: [:],

    maxExecsBeforeRespawn: 1000,

    timeout: Timeout.interval(300, 900),

    codePrefix: """
                \(v8JITOracleHelpers)
                """,

    codeSuffix: """
                """,

    ecmaVersion: ECMAScriptVersion.es6,

    startupTests: [
        // Check that the fuzzilli integration is available.
        ("fuzzilli('FUZZILLI_PRINT', 'test')", .shouldSucceed),

        // Check that common crash types are detected.
        // IMMEDIATE_CRASH()
        ("fuzzilli('FUZZILLI_CRASH', 0)", .shouldCrash),
        // CHECK failure
        ("fuzzilli('FUZZILLI_CRASH', 1)", .shouldCrash),
        // DCHECK failure
        ("fuzzilli('FUZZILLI_CRASH', 2)", .shouldCrash),
        // Wild-write
        ("fuzzilli('FUZZILLI_CRASH', 3)", .shouldCrash),
        // Check that DEBUG is defined.
        ("fuzzilli('FUZZILLI_CRASH', 8)", .shouldCrash),

        // TODO we could try to check that OOM crashes are ignored here ( with.shouldNotCrash).
    ],

    additionalCodeGenerators: [
        (ForceJITCompilationThroughLoopGenerator,  5),
        (ForceTurboFanCompilationGenerator,        5),
        (ForceMaglevCompilationGenerator,          5),
        (TurbofanVerifyTypeGenerator,             10),

        (WorkerGenerator,                         10),
        (V8GcGenerator,                           10),

        (WasmStructGenerator,                     15),
        (WasmArrayGenerator,                      15),
        (SharedObjectGenerator,                    5),
        (PretenureAllocationSiteGenerator,         5),
        (HoleNanGenerator,                         5),
        (UndefinedNanGenerator,                    5),
        (StringShapeGenerator,                     5),
    ],

    additionalProgramTemplates: WeightedList<ProgramTemplate>([
        (MapTransitionFuzzer,     1),
        (ValueSerializerFuzzer,   1),
        (V8RegExpFuzzer,          1),
        (WasmFastCallFuzzer,      1),
        (FastApiCallFuzzer,       1),
        (LazyDeoptFuzzer,         1),
        (WasmDeoptFuzzer,         1),
        (WasmTurbofanFuzzer,      1),
        (ProtoAssignSeqOptFuzzer, 1),
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

    optionalPostProcessor: V8JITOraclePostProcessor()
)

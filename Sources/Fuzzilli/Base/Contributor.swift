// Copyright 2020 Google LLC
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

/// Something that contributes to the creation of a program.
/// This class is used to compute detailed statistics about correctness and timeout rates as well as the number of interesting or crashing programs generated, etc.
public class Contributor: Hashable {
    // The name of this contributor so that it's easy to identify it in statistics.
    public let name: String

    // Number of valid programs produced (i.e. programs that run to completion)
    private var validSamples = 0
    // Number of interesting programs produces (i.e. programs that triggered new interesting behavior). All interesting programs are also valid.
    private var interestingSamples = 0
    // Number of invalid programs produced (i.e. programs that raised an exception or timed out)
    private var invalidSamples = 0
    // Number of produced programs that resulted in a timeout.
    private var timedOutSamples = 0
    // Number of crashing programs produced.
    private var crashingSamples = 0
    // The number of times this contributor has been invoked
    private(set) var invocationCount = 0
    // The number of times this contributor has actually emitted more than 0 instructions
    private var successfulGenerationCount = 0

    // Number of times this instance failed to generate/mutate code.
    private var failures = 0
    // Total number of instructions added to programs by this contributor.
    private var totalInstructionProduced = 0

    // Direct outcome statistics for the contributor instance currently selected by the engine.
    // These are intentionally not propagated through a program's parent chain and are mainly used
    // for adaptive scheduling.
    private var directValidSamples = 0
    private var directInterestingSamples = 0
    private var directInvalidSamples = 0
    private var directTimedOutSamples = 0
    private var directCrashingSamples = 0
    private var directFailures = 0

    public init(name: String) {
        self.name = name
    }

    func generatedValidSample() {
        validSamples += 1
    }

    func generatedInterestingSample() {
        interestingSamples += 1
    }

    func generatedInvalidSample() {
        invalidSamples += 1
    }

    func generatedTimeOutSample() {
        timedOutSamples += 1
    }

    func generatedCrashingSample() {
        crashingSamples += 1
    }

    func invoked() {
        invocationCount += 1
    }

    func addedInstructions(_ n: Int) {
        assert(n >= 0)
        totalInstructionProduced += n
        if n > 0 {
            successfulGenerationCount += 1
        }
    }

    func failedToGenerate() {
        failures += 1
    }

    func recordDirectValidSample() {
        directValidSamples += 1
    }

    func recordDirectInterestingSample() {
        directInterestingSamples += 1
    }

    func recordDirectInvalidSample() {
        directInvalidSamples += 1
    }

    func recordDirectTimeOutSample() {
        directTimedOutSamples += 1
    }

    func recordDirectCrashingSample() {
        directCrashingSamples += 1
    }

    func recordDirectFailure() {
        directFailures += 1
    }

    public var crashesFound: Int {
        return crashingSamples
    }

    public var totalSamples: Int {
        return validSamples + interestingSamples + invalidSamples + timedOutSamples + crashingSamples
    }

    public var directValidSampleCount: Int {
        return directValidSamples
    }

    public var directInterestingSampleCount: Int {
        return directInterestingSamples
    }

    public var directInvalidSampleCount: Int {
        return directInvalidSamples
    }

    public var directTimeOutSampleCount: Int {
        return directTimedOutSamples
    }

    public var directCrashSampleCount: Int {
        return directCrashingSamples
    }

    public var directFailureCount: Int {
        return directFailures
    }

    public var directTotalSamples: Int {
        return directValidSamples + directInterestingSamples + directInvalidSamples + directTimedOutSamples + directCrashingSamples
    }

    public var directAttempts: Int {
        return directTotalSamples + directFailures
    }

    // If this is low, that means the CodeGenerator has dynamic requirements that are not met most of the time.
    public var invocationSuccessRate: Double? {
        guard invocationCount > 0 else { return nil }
        return Double(successfulGenerationCount) / Double(invocationCount)
    }

    public var correctnessRate: Double? {
        guard totalSamples > 0 else { return nil }
        return Double(validSamples + interestingSamples) / Double(totalSamples)
    }

    public var interestingSamplesRate: Double? {
        guard totalSamples > 0 else { return nil }
        return Double(interestingSamples) / Double(totalSamples)
    }

    public var timeoutRate: Double? {
        guard totalSamples > 0 else { return nil }
        return Double(timedOutSamples) / Double(totalSamples)
    }

    public var failureRate: Double? {
        let totalAttempts = totalSamples + failures
        guard totalAttempts > 0 else { return nil }
        return Double(failures) / Double(totalAttempts)
    }

    public var directCorrectnessRate: Double? {
        guard directTotalSamples > 0 else { return nil }
        return Double(directValidSamples + directInterestingSamples) / Double(directTotalSamples)
    }

    public var directInterestingSamplesRate: Double? {
        guard directTotalSamples > 0 else { return nil }
        return Double(directInterestingSamples) / Double(directTotalSamples)
    }

    public var directTimeoutRate: Double? {
        guard directTotalSamples > 0 else { return nil }
        return Double(directTimedOutSamples) / Double(directTotalSamples)
    }

    public var directCrashRate: Double? {
        guard directTotalSamples > 0 else { return nil }
        return Double(directCrashingSamples) / Double(directTotalSamples)
    }

    public var directFailureRate: Double? {
        guard directAttempts > 0 else { return nil }
        return Double(directFailures) / Double(directAttempts)
    }

    // Note: even if for example a CodeGenerator always generates exactly one instruction, this number may be
    // slightly higher than one as the same CodeGenerator may run multiple times to generate one program.
    public var avgNumberOfInstructionsGenerated: Double {
        guard totalSamples > 0 else { return 0.0 }
        return Double(totalInstructionProduced) / Double(totalSamples)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }

    public static func == (lhs: Contributor, rhs: Contributor) -> Bool {
        return lhs === rhs
    }
}

/// All "things" (Mutators, CodeGenerators, ProgramTemplates, ...) that contributed directly (i.e. not including parent programs) to the creation of a particular program.
public typealias Contributors = Set<Contributor>
extension Contributors {
    public func generatedValidSample() {
        forEach { $0.generatedValidSample() }
    }

    public func generatedInterestingSample() {
        forEach { $0.generatedInterestingSample() }
    }

    public func generatedInvalidSample() {
        forEach { $0.generatedInvalidSample() }
    }

    public func generatedCrashingSample() {
        forEach { $0.generatedCrashingSample() }
    }

    public func generatedTimeOutSample() {
        forEach { $0.generatedTimeOutSample() }
    }
}

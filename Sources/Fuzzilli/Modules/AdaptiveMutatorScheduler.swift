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

import Foundation

/// Reweights mutators online using direct outcome statistics from the mutator that was
/// selected for the current execution.
///
/// The implementation intentionally keeps the original weight distribution as a prior and only
/// nudges weights based on a mutator's reward per attempt and an exploration bonus. This makes
/// the scheme robust enough for long-running V8 fuzzing without letting one mutator collapse the
/// search space too early.
public class AdaptiveMutatorScheduler: Module {
    private let updateInterval: TimeInterval
    private let minimumSamplesPerMutator: Int
    private let logger = Logger(withLabel: "AdaptiveMutatorScheduler")

    private var baseWeightsByName: [String: Int] = [:]
    private var lastWeightsByName: [String: Int] = [:]

    public init(updateInterval: TimeInterval = 120.0, minimumSamplesPerMutator: Int = 32) {
        self.updateInterval = updateInterval
        self.minimumSamplesPerMutator = minimumSamplesPerMutator
    }

    public func initialize(with fuzzer: Fuzzer) {
        let initialWeights = Dictionary(uniqueKeysWithValues: fuzzer.mutators.iteratorWithWeights().map { ($0.0.name, $0.1) })
        self.baseWeightsByName = initialWeights
        self.lastWeightsByName = initialWeights

        fuzzer.timers.scheduleTask(every: updateInterval) {
            self.rebalanceMutators(on: fuzzer)
        }
    }

    private func rebalanceMutators(on fuzzer: Fuzzer) {
        var totalAttempts = 0
        for mutator in fuzzer.mutators {
            totalAttempts += mutator.directAttempts
        }

        guard totalAttempts >= minimumSamplesPerMutator else { return }

        var newWeights = WeightedList<Mutator>()
        var changed = false
        var summary = [String]()

        for (mutator, _) in fuzzer.mutators.iteratorWithWeights() {
            let baseWeight = baseWeightsByName[mutator.name] ?? 1
            let newWeight = computeWeight(for: mutator, baseWeight: baseWeight, totalAttempts: totalAttempts)
            newWeights.append(mutator, withWeight: newWeight)
            summary.append("\(mutator.name)=\(newWeight)")
            changed = changed || lastWeightsByName[mutator.name] != newWeight
        }

        guard changed else { return }

        fuzzer.setMutators(newWeights)
        self.lastWeightsByName = Dictionary(uniqueKeysWithValues: newWeights.iteratorWithWeights().map { ($0.0.name, $0.1) })
        logger.info("Adjusted mutator weights: \(summary.joined(separator: ", "))")
    }

    private func computeWeight(for mutator: Mutator, baseWeight: Int, totalAttempts: Int) -> Int {
        let attempts = mutator.directAttempts
        guard attempts >= minimumSamplesPerMutator else { return baseWeight }

        let reward =
            0.6 * Double(mutator.directValidSampleCount) +
            40.0 * Double(mutator.directInterestingSampleCount) +
            80.0 * Double(mutator.directCrashSampleCount)
        let penalties =
            1.0 * Double(mutator.directInvalidSampleCount) +
            4.0 * Double(mutator.directTimeOutSampleCount) +
            2.0 * Double(mutator.directFailureCount)

        let prior = 8.0 * Double(baseWeight)
        let empiricalScore = max(0.0, reward - penalties + prior) / Double(attempts + 8 * baseWeight)
        let explorationBonus = 1.25 * sqrt(log(Double(totalAttempts) + 1.0) / Double(attempts + 1))
        let boundedMultiplier = min(3.5, max(0.35, empiricalScore + explorationBonus))

        let maxWeight = max(baseWeight * 4, 4)
        return max(1, min(maxWeight, Int(round(Double(baseWeight) * boundedMultiplier))))
    }
}

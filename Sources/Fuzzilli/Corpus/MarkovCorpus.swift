import Foundation

/// Corpus & Scheduler based on
/// Coverage-based Greybox Fuzzing as Markov Chain paper
/// https://mboehme.github.io/paper/TSE18.pdf
/// Simply put, the corpus keeps track of which paths have been found, and prioritizes seeds
/// whose path has been hit less than average. Ideally, this allows the fuzzer to prioritize
/// less explored coverage.
/// In the paper, a number of iterations is assigned to each sample, and each sample is then
/// scheduled that number of times. This implementation finds 1 / desiredSelectionProportion
/// of the least hit edges, and schedules those. After those have been mutated and evalutated,
/// the list is regenerated.

public class MarkovCorpus: ComponentBase, Corpus {
    private struct ProgramCandidate {
        let program: Program
        var rareEdgeHits: Int
        var minEdgeHitCount: UInt32
    }

    // All programs that were added to the corpus so far
    private var allIncludedPrograms: [Program] = []
    // Queue of programs to be executed next, all of which hit a rare edge
    private var programExecutionQueue: [Program] = []

    // For each edge encountered thus far, track which program initially discovered it
    private var edgeMap: [UInt32:Program] = [:]

    // This scheduler tracks the total number of samples it has returned
    // This allows it to build an initial baseline by randomly selecting a program to mutate
    // before switching to the more computationally expensive selection of programs that
    // hit infreqent edges
    private var totalExecs: UInt32 = 0

    // This scheduler returns one base program multiple times, in order to compensate the overhead caused by tracking
    // edge counts
    private var currentProg: Program
    private var remainingEnergy: UInt32 = 0

    // Markov corpus requires an evaluator that tracks edge coverage
    // Thus, the corpus object keeps a reference to the evaluator, in order to only downcast once
    private var covEvaluator: ProgramCoverageEvaluator

    // Rate at which selected samples will be included, to promote diversity between instances
    // Equivalent to 1 - dropoutRate
    private var dropoutRate: Double

    // Per-program execution times are used to bias the seed energy towards faster samples.
    private var executionTimesByProgramId: [UUID: TimeInterval] = [:]
    private var totalExecutionTime: TimeInterval = 0

    // The scheduler will initially selectd the 1 / desiredSelectionProportion samples with the least frequent
    // edge hits in each round, before dropout is applied
    private let desiredSelectionProportion = 8

    public init(covEvaluator: ProgramCoverageEvaluator, dropoutRate: Double) {
        self.dropoutRate = dropoutRate
        covEvaluator.enableEdgeTracking()
        self.covEvaluator = covEvaluator
        self.currentProg = Program()
        super.init(name: "MarkovCorpus")
    }

    override func initialize() {
        assert(covEvaluator === fuzzer.evaluator as! ProgramCoverageEvaluator)
    }

    public func add(_ program: Program, _ aspects: ProgramAspects) {
        guard program.size > 0 else { return }

        guard let origCov = aspects as? CovEdgeSet else {
            logger.fatal("Markov Corpus needs to be provided a CovEdgeSet when adding a program")
        }

        prepareProgramForInclusion(program, index: self.size)

        allIncludedPrograms.append(program)
        let executionTime = max(origCov.executionTime, 0.000_001)
        if let previousTime = executionTimesByProgramId.updateValue(executionTime, forKey: program.id) {
            totalExecutionTime -= previousTime
        }
        totalExecutionTime += executionTime
        for e in origCov.getEdges() {
            edgeMap[e] = program
        }
    }

    /// Split evenly between programs in the current queue and all programs available to the corpus
    public func randomElementForSplicing() -> Program {
        var prog = programExecutionQueue.randomElement()
        if prog == nil || probability(0.5) {
            prog = allIncludedPrograms.randomElement()
        }
        assert(prog != nil && prog!.size > 0)
        return prog!
    }

    /// For the first 250 executions, randomly choose a program. This is done to build a base list of edge counts
    /// Once that base is acquired, provide samples that trigger an infrequently hit edge
    public func randomElementForMutating() -> Program {
        totalExecs += 1
        // Only do computationally expensive work choosing the next program when there is a solid
        // baseline of execution data. The data tracked in the statistics module is not used, as modules are intended
        // to not be required for the fuzzer to function.
        if totalExecs > 250 {
            // Check if more programs are needed
            if programExecutionQueue.isEmpty {
                regenProgramList()
            }
            if remainingEnergy > 0 {
                remainingEnergy -= 1
            } else {
                currentProg = programExecutionQueue.popLast()!
                let energy = max(energyForProgram(currentProg), 1)
                remainingEnergy = energy - 1
            }
            return currentProg
        } else {
            return allIncludedPrograms.randomElement()!
        }
    }

    private func regenProgramList() {
        if programExecutionQueue.count != 0 {
            logger.fatal("Attempted to generate execution list while it still has programs")
        }
        let edgeCounts = covEvaluator.getEdgeHitCounts()
        let edgeCountsSorted = edgeCounts.sorted()

        // Find the edge with the smallest count
        var startIndex = -1
        for (i, val) in edgeCountsSorted.enumerated() {
            if val != 0 {
                startIndex = i
                break
            }
        }
        if startIndex == -1 {
            logger.fatal("No edges found in edge count")
        }

        // Find the nth interesting edge's count
        let desiredEdgeCount = max(size / desiredSelectionProportion, 30)
        let endIndex = min(startIndex + desiredEdgeCount, edgeCountsSorted.count - 1)
        let maxEdgeCountToFind = edgeCountsSorted[endIndex]

        var candidates = collectCandidates(from: edgeCounts, maxEdgeCountToFind: maxEdgeCountToFind, applyDropout: true)
        if candidates.isEmpty {
            candidates = collectCandidates(from: edgeCounts, maxEdgeCountToFind: maxEdgeCountToFind, applyDropout: false)
        }
        let averageExecutionTime = averageExecutionTimeInCorpus()
        let prioritizedPrograms = candidates.values.sorted {
            prioritizationScore(for: $0, averageExecutionTime: averageExecutionTime) <
            prioritizationScore(for: $1, averageExecutionTime: averageExecutionTime)
        }.map(\.program)
        programExecutionQueue.append(contentsOf: prioritizedPrograms)

        // Determine how many edges have been leaked and produce a warning if over 1% of total edges
        // Done as second pass for code clarity
        // Testing on v8 shows that < 0.01% of total edges are leaked
        // Potential causes:
        //  - Libcoverage iterates over the edge map twice, once for new coverage, and once for edge counts.
        //      This occurs while the target JS engine is running, so the coverage may be slightly different between the passes
        //      However, this is unlikely to be useful coverage for the purposes of Fuzzilli
        //  - Crashing samples may find new coverage and thus increment counters, but are not added to the corpus
        var missingEdgeCount = 0
        for (i, val) in edgeCounts.enumerated() {
            if val != 0 && edgeMap[UInt32(i)] == nil {
                missingEdgeCount += 1
            }
        }
        if missingEdgeCount > (edgeCounts.count / 100) {
            let missingPercentage = Double(missingEdgeCount) / Double(edgeCounts.count) * 100.0
            logger.warning("\(missingPercentage)% of total edges have been leaked")
        }

        if programExecutionQueue.count == 0 {
            logger.fatal("Program regeneration failed")
        }
        logger.info("Markov Corpus selected \(programExecutionQueue.count) new programs, average seed exec time \(String(format: "%.2f", averageExecutionTime * 1000))ms")
    }

    public var size: Int {
        return allIncludedPrograms.count
    }

    public var isEmpty: Bool {
        return size == 0
    }

    public subscript(index: Int) -> Program {
        return allIncludedPrograms[index]
    }

    public func allPrograms() -> [Program] {
        return allIncludedPrograms
    }

    // We don't currently support fast state synchronization.
    // Instead, we need to import every sample separately (potentially
    // multiple times for determinism) to determine the edges it triggers.
    public var supportsFastStateSynchronization: Bool {
        return false
    }

    // Note that this exports all programs, but does not include edge counts
    public func exportState() throws -> Data {
        fatalError("Not Supported")
    }

    public func importState(_ buffer: Data) throws {
        fatalError("Not Supported")
    }

    // Ramp up the number of times a sample is used as the initial seed over time
    private func energyBase() -> UInt32 {
        return UInt32(Foundation.log10(Float(totalExecs))) + 1
    }

    private func collectCandidates(from edgeCounts: [UInt32], maxEdgeCountToFind: UInt32, applyDropout: Bool) -> [UUID: ProgramCandidate] {
        var candidates = [UUID: ProgramCandidate]()

        for (index, hitCount) in edgeCounts.enumerated() {
            guard hitCount != 0 && hitCount <= maxEdgeCountToFind else { continue }
            guard !applyDropout || probability(1 - dropoutRate) else { continue }
            guard let program = edgeMap[UInt32(index)] else { continue }

            if var current = candidates[program.id] {
                current.rareEdgeHits += 1
                current.minEdgeHitCount = min(current.minEdgeHitCount, hitCount)
                candidates[program.id] = current
            } else {
                candidates[program.id] = ProgramCandidate(program: program, rareEdgeHits: 1, minEdgeHitCount: hitCount)
            }
        }

        return candidates
    }

    private func averageExecutionTimeInCorpus() -> TimeInterval {
        guard !executionTimesByProgramId.isEmpty else {
            return Double(fuzzer.config.timeout) / 1000.0
        }
        return max(totalExecutionTime / Double(executionTimesByProgramId.count), 0.000_001)
    }

    private func executionTime(of program: Program) -> TimeInterval {
        return max(executionTimesByProgramId[program.id] ?? averageExecutionTimeInCorpus(), 0.000_001)
    }

    private func prioritizationScore(for candidate: ProgramCandidate, averageExecutionTime: TimeInterval) -> Double {
        let rarityScore = Double(candidate.rareEdgeHits) / Double(max(candidate.minEdgeHitCount, 1))
        let speedScore = min(4.0, max(0.5, sqrt(averageExecutionTime / executionTime(of: candidate.program))))
        return rarityScore * speedScore
    }

    private func energyForProgram(_ program: Program) -> UInt32 {
        let baseEnergy = max(Double(energyBase()), 1.0)
        let speedScore = min(4.0, max(0.5, sqrt(averageExecutionTimeInCorpus() / executionTime(of: program))))
        return UInt32(max(1.0, round(baseEnergy * speedScore)))
    }
}

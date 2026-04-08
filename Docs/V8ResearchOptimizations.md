# V8 Research Optimizations

This tree was updated with low-risk scheduler changes that are practical for long-running V8 fuzzing.

Implemented now:

* Time-aware rare-edge scheduling in `MarkovCorpus`. Newly interesting seeds now keep their execution time, and rare-edge candidates are prioritized by a combined rarity/speed score before energy is assigned. This follows the broad direction of recent work that optimizes reward per unit time instead of treating all seeds as equally expensive.
* Online adaptive mutator reweighting in `AdaptiveMutatorScheduler`. The scheduler reweights mutators from direct outcomes of the mutator chosen by the engine, which is closer to recent adaptive operator scheduling work than the previous fixed-weight approach.
* A V8 JIT-consistency oracle inspired by FuzzJIT. A subset of generated non-Wasm programs is wrapped in an optimization harness that compares observable outputs before and after `%OptimizeFunctionOnNextCall`. This extends the fork beyond crash-only discovery and gives it a path to expose non-crashing JIT miscompilations.
* A V8-focused launch path in `Tools/run-v8-fuzz.sh` that pins the workflow to the `v8` profile and enables `markov`, `--argumentRandomization`, and `--swarmTesting`.

Recent work used as guidance:

* AMSFuzz (2022): adaptive mutation operator scheduling with bandit-style feedback.
  https://doi.org/10.1016/j.eswa.2022.118162
* FuzzJIT (USENIX Security 2023): oracle-enhanced fuzzing for JavaScript engine JIT compilers.
  https://www.usenix.org/conference/usenixsecurity23/presentation/wang-junjie
* SJFuzz (ESEC/FSE 2023): seed and mutator scheduling for JVM fuzzing.
  https://2023.esec-fse.org/details/fse-2023-research-papers/36/SJFuzz-Seed-Mutator-Scheduling-for-JVM-Fuzzing
* FOX (2024): coverage-guided fuzzing as online stochastic control.
  https://researchportal.hkust.edu.hk/en/publications/fox-coverage-guided-fuzzing-as-online-stochastic-control-3/
* LOOL (ISSTA 2024): optimization-log-guided compiler fuzzing.
  https://research.jku.at/en/publications/lool-low-overhead-optimization-log-guided-compiler-fuzzing/

Not implemented yet:

* Full optimization-log-guided feedback for V8, as in LOOL. That would require parsing V8 optimization logs and feeding those compiler events into the evaluator or corpus scheduler.
* Seed slicing / region-aware mutation. That is more invasive in FuzzIL than in AFL-style byte mutators and should be done separately if needed.

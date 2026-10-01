# Evaluation

What the reviewer measurably catches, how that is measured, and every change that
was tried against it - including the ones that did not survive.

---

## Method

**Cases.** Held out of the securecode corpus rather than hand-written: each entry
ships an expert-written vulnerable/secure code pair with CWE, technique and
severity labels. Two disjoint sets of 40 pairs:

| Set | File | Use |
|---|---|---|
| dev | `datasets/dev.jsonl` | iterate on changes |
| gold | `datasets/gold.jsonl` | measure a finished change, under a rule written beforehand |

**Two metrics, one per half of each pair.**

- **Detection** - the vulnerable snippet produces a finding that identifies the
  labelled flaw.
- **False positives** - the fixed snippet is flagged *for the labelled flaw*. A
  reviewer that flags everything scores 100% detection and is useless, so
  detection alone is a vanity metric.

**Paired comparison.** Both configurations review the same cases, so only cases
whose verdict changed carry information: McNemar's exact test on those discordant
pairs (`evals.compare`).

**A pre-registered acceptance rule.** Committed in `ce44853`, before the first gold
result it judged was read: a change ships if detection falls by at most **1** case
net and false positives fall by at least **3** cases net. p is reported but does
not decide - at n = 40 almost no real change reaches p < 0.05.

**The shipped code path.** The suite drives the real nodes (`get_context`,
`retrieve_examples`, `security_agent`), so the numbers describe the agent the
webhook calls, not a reimplementation of it. Every report records the model, its
options and the Ollama version that produced it.

---

## Current result

**qwen3.5:9b replaced llama3.2 as the reviewer.** Ollama 0.35.0, one judge, no
retrieval (the shipped configuration for diffs of this size):

| | llama3.2 | qwen3.5:9b | paired |
|---|---:|---:|---|
| **gold** detection | 0.949 | **0.974** | 1 gained, 0 lost, p = 1.0 |
| **gold** false positives | 0.436 | **0.179** | 15 cleared, 5 new, **p = 0.041** |
| dev detection | 0.763 | 0.947 | 7 gained, 0 lost, p = 0.016 |
| dev false positives | 0.421 | 0.053 | 16 cleared, 2 new, p = 0.001 |

39 paired gold cases, 38 dev. Under the pre-registered rule: **ship**.

The mechanism is visible in what each model produces. On gold, llama3.2 gives
**4.05 findings per fixed snippet and 4.05 per vulnerable one** - it does not tell
them apart, and its false positives are generic noise. qwen gives 1.23 on fixed
code and 2.87 on vulnerable, leaves 18 of 39 fixed snippets empty, and never
leaves a vulnerable one empty.

The robust effect is false positives, which replicated across both sets. Dev's
detection gain did not replicate at full size: on gold llama3.2 already detects
95%, leaving little room. The price is speed and memory: a median **57 s per file
against 25 s**, and ~16 GB of RAM.

---

## The judge

The reviewer's findings are free text, so a finding counts as identifying the
labelled flaw if an LLM judge (`gemma4:e4b`, deliberately not a reviewing model)
says it does - in any wording. A finding that names the right line but claims the
wrong flaw is a miss.

It replaced substring probes on the technique name, which marked 16 correct
findings as misses and 5 wrong ones as hits: a reviewer that wrote *"no
authorization check on admin routes"* was scored as missing *forced browsing*.

**Validated against human labels** on 30 findings (`datasets/judge_validation.jsonl`).
8 of them share a technique with the prompt's worked examples, which were written
from the same reports, so the 22 that do not are the number to trust:

| Cohen's kappa vs human | all 30 | uncontaminated 22 |
|---|---:|---:|
| substring probes | 0.27 | 0.37 |
| judge, Ollama 0.30.10 | 0.79 | 0.72 |
| judge, Ollama 0.35.0 | **0.84** | **0.89** |

On 0.35.0 both of its remaining errors are over-generous; on 0.30.10 all three
were over-strict. Either way the error applies to both arms of a comparison alike.

**It sees descriptions only** - its validated condition. Shown fix text as well, it
flipped 4 verdicts on 45 word-identical findings, all True to False, 3 of them
against the human labels.

**Its cache is keyed by model, prompt and runtime.** A prompt edit or an Ollama
update cannot serve the previous judge's verdicts inside a new comparison: on
0.35.0 it changed 5 of the 30 validation verdicts it gave on 0.30.10.

---

## Experiment log

In order. Everything before the model change ran llama3.2 on Ollama 0.30.10;
numbers from different runtimes are not comparable, because the runtime changes
the judge as well as the reviewer.

### 1. Retrieval: switched off below 20,000 characters

The original design retrieved three similar vulnerability examples into every
review. Measured over two runs on gold:

| Paired cases | RAG | No-RAG | McNemar |
|---|---:|---:|---|
| detection, run 1 (n = 39) | 0.795 | 0.821 | p = 1.0 |
| detection, run 2 (n = 36) | 0.917 | 0.861 | p = 0.63 |
| false positives, run 2 (n = 36) | 0.500 | 0.389 | p = 0.42 |

No measurable effect on either metric; the direction of the detection difference
flipped between runs. Two things retrieval did do:

- **It made results irreproducible.** Across the two identical runs, no-RAG's
  detection verdicts matched on 39 of 39 cases; RAG's changed on 6 of 37.
- **It put its examples' vulnerability names into the findings.** 33 of 231 RAG
  findings (14%) named a technique that retrieval had put in the prompt, against
  0 of 313 without it. On a 14-line SQL injection demo, the reviewer reported
  *Missing MFA*, *Remember me vulnerabilities* and *Insecure password change* -
  the three retrieved documents, at line numbers past the end of the 14-line
  diff - and missed the injection.

So retrieval now runs only for diffs of at least `RETRIEVAL_MIN_CHARS` (20,000)
characters, ten times the largest diff the evaluation covers. Whether it helps on
large diffs is untested.

### 2. Quoted evidence for every finding: rejected on gold, reverted

Each finding quoted the line it was about; findings whose quote was not in the
diff were dropped, and line numbers were computed from the quote.

| | before | after | paired |
|---|---:|---:|---|
| dev false positives | 0.385 | 0.231 | 8 cleared, 2 new, p = 0.11 |
| gold false positives | 0.385 | **0.436** | 6 cleared, 8 new |
| gold detection | 0.846 | **0.795** | 2 gained, 4 lost |

Both halves of the pre-registered rule failed on gold, so it was reverted
(`80940d0`). Pooled over both sets there is no evidence of a false-positive
benefit (p = 0.54). What replicated is that quoting first made the reviewer about a
third quieter, which cost detections. The dev number was also slightly flattered:
the first quote matcher discarded statements the model rejoined across lines, a
bug found and fixed on dev.

### 3. qwen3.5:9b: shipped

Three obstacles, each found by a gated one-case probe before a full run:

- **It thinks until the output cap.** With 1,536 tokens it spent them all on hidden
  reasoning and returned nothing. Thinking off (`REVIEW_THINK=off`) needed
  langchain-ollama 0.3.10; the upgrade was shown not to change llama3.2's requests
  by capturing them, byte for byte, with a fake Ollama server.
- **Ollama 0.30.10 dropped the JSON schema for it with thinking off.** A tool-call
  route worked, but on 18 of 36 fixed snippets qwen answered in prose instead of
  calling the tool. Those were first scored as clean - and 3 of 4 sampled turned
  out to describe the very flaw the code had been fixed for. That run's
  false-positive rate is invalid, and a missing tool call is now an error.
- **Ollama 0.35.0 enforces the schema**, which removed the problem at the root. On
  the new runtime, llama3.2's dev detection verdicts were unchanged (0 of 38),
  though its wording changed on 36 of 38.

Then the result above.

### Effects that did not survive

Each looked real at n = 40 until the measurement improved:

1. The first evidence that retrieval misdirects the model - a substring-scoring
   artefact. Measured directly later, the effect itself is real (see 1).
2. Retrieval silencing the reviewer on specific cases - both were detected on the
   next run.
3. A false-positive gap at p = 0.09 between the RAG arms - the judge seeing fix text.
4. Quoted evidence cutting false positives by 40% - true of dev only.
5. qwen halving false positives on the tool-call route - prose answers scored as
   clean.

---

## Decisions worth explaining

**Cases are held out by content, not by id.** The corpus id is not an identifier:
`dataset.py` concatenates splits that each number from one, so
`authentication-000002` names 21 unrelated documents. Holding out by id would have
dropped about twenty innocent siblings per case from retrieval and biased the RAG
arm downward.

**A false positive is the labelled flaw only.** An earlier definition, any finding
at all on fixed code, sat at 1.000 and carried no signal: a secure version fixes
its own vulnerability, not every unrelated wart.

**Pipeline first, judge second.** The reviewer and the judge do not fit in memory
together, so the pipeline runs with `--scorer substring` and `evals.judge rescore`
grades the stored findings afterwards. The result is the same, and each model
loads once.

**Reports are committed.** Each one is the evidence for a claim, and a diff
between two is the record of what a change did.

---

## Limitations

1. **n = 40.** Effects under roughly 15 points are hard to see.
2. **The gold set has informed three decisions** - retrieval, quoted evidence and
   the model. It is overdue for replacement; 1,006 unused pairs remain.
3. **One annotator, who is also the author,** labelled the judge's 30 validation items.
4. **Only the labelled flaw is scored.** Other findings on the same code are neither
   credited nor penalised.
5. **The code-quality agent is not evaluated at all.**
6. **Temperature 0 is not determinism** on this stack.
7. **Some reviews hit a repetition loop** - dozens of findings where a normal review
   has three or four - and fail to parse; they are excluded from paired comparisons.
8. **Retrieval with qwen3.5:9b is untested.**

---

## Running it

```bash
# Build the sets (one-time); the dev set excludes everything in gold by content
python -m evals.build_gold --n 40
python -m evals.build_gold --n 40 --seed 1 --exclude evals/datasets/gold.jsonl --out evals/datasets/dev.jsonl

# Review, then grade (the reviewer and judge are loaded one at a time)
python -m evals.run --no-rag --scorer substring --label my-change
python -m evals.judge rescore evals/reports/my-change.json

# Paired comparison and verdict under the pre-registered rule
python -m evals.compare evals/reports/BEFORE-judged.json evals/reports/my-change-judged.json

# Checks that need no model
python -m evals.run --self-check
python -m evals.compare --self-check

# Judge validation sheet
python -m evals.judge label
python -m evals.judge agreement
```

To reproduce a llama3.2 baseline exactly as it was measured, run with
`REVIEW_MODEL=llama3.2 REVIEW_THINK=` - that sends byte-identical requests.

---

## Next

1. **A fresh held-out set**, replacing gold for the next decision.
2. **Line numbers.** The model counts them and is often off by a few lines.
3. **Cap `num_ctx`.** qwen3.5:9b loads its full 262k context; capping it would cut
   its memory, measured as its own change.
4. **Retrieval with qwen3.5:9b**, on large diffs where it might earn its place.

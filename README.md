# Sealed Evaluation Pattern

Check whether an evaluation record kept its test material out of generation
and review until the declared reveal. This small Python checker compares the
recorded order of events and file digests—fingerprints of the file contents.

Start with the synthetic good case below, then run the self-test to see which
mistakes it catches. You do not need a model, network connection or extra
packages. All bundled text is synthetic.

## Run

Requires Python 3.10 or newer. Run these commands from the repository root:

```sh
python3 -B sealed_eval.py examples/good.json
python3 -B sealed_eval.py --self-test
python3 -B -m unittest discover -s tests -v
```

Expected result for the good case:

```text
PASS sealed_evaluation good.json
```

The self-test checks that the good fixture passes and that examples with sealed
access, bad freeze order, a changed output, an unretired reveal, or a
calibration input fail with named finding codes. An expected rejection is a
passing test of the checker; it is not a successful evaluation run.

<!-- toolkit-trust-card:placement -->

<!-- toolkit-trust-card:start -->
> **Public contract:** Experimental pattern · about 10 min · Python 3 · no model · no network
>
> **Operation:** Read-only check; examples may use temporary files
>
> **A pass establishes:** The supplied record preserves the declared information zones, freeze order, digests, and retirement rule.
>
> **It does not establish:** The checker is not a sandbox and cannot prove an access log is complete or authentic.
>
> **First check:** `python3 -B sealed_eval.py --self-test`
<!-- toolkit-trust-card:end -->

## Why It Exists

A corpus is the collection of material you use for an evaluation. When that
collection is small, revealing a test item changes what you can claim about
the next run. Once a target has influenced generation or review, it cannot
honestly remain a blind holdout—material kept unseen until testing.

The pattern separates material into three zones: **learning** material may
help generation, **calibration** material can be revealed for a named
comparison, and **sealed** material must stay unseen. The recorded steps are:

1. Declare the information zones before the run.
2. Allow generation to use learning material only.
3. Freeze the output and pre-reveal review.
4. Reveal one named calibration target.
5. Compare, then retire the revealed target.
6. Invalidate the blind claim if sealed material was accessed.

## Case Contract

Each case file tells the checker what was allowed and what was recorded:

- sources and their `learning`, `calibration`, or `sealed` zones;
- the only source IDs authorized as generation input;
- one calibration target;
- a generated-output path and SHA-256 digest;
- timestamped access, freeze, review, and reveal events;
- revealed source IDs retired from future blind evaluation; and
- whether contamination was detected.

The checker calculates digests for accessed learning and calibration files
and for the generated output, then compares them with the record. It leaves
unaccessed sealed files unopened.

## What A Pass Establishes

For the supplied record and local files, a pass establishes that:

- generation inputs were declared in the learning zone;
- the output and pre-reveal review were frozen before calibration reveal;
- declared source access did not include sealed material or early calibration;
- accessed-file and output digests match;
- the named calibration target was revealed and retired; and
- the run is not declared contaminated.

## What It Does Not Establish

The checker tests relationships in the record you supply. It is not a sandbox
or an attestation system: it does not enforce isolation or authenticate the
record. It does not prove that an access log is complete, authenticate timestamps or people,
prevent another process from reading sealed data, judge model quality, or make
a publication decision. Real evaluations still need operating-system or data
access controls and an independent review of the record.

## Public Data Notice

This repository contains synthetic fixtures only. Do not add manuscripts,
private datasets, personal notes, model transcripts, credentials, or real
holdout content to examples or issues.

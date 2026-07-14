# Sealed Evaluation Pattern

A small, dependency-free checker for preserving an information boundary during
evaluation against a scarce corpus.

The pattern separates learning, calibration, and sealed material; freezes a
generated output and human judgement before reveal; checks declared access
order and file digests; and requires revealed calibration material to be
retired from future blind tests.

All bundled text is synthetic. The checker does not call a model or use the
network.

## Why It Exists

When only one useful corpus exists, careless evaluation consumes the test set.
Once a target has influenced generation or review, it cannot honestly remain a
blind holdout.

This repository makes the minimum protocol inspectable:

1. Declare the information zones before the run.
2. Allow generation to use learning material only.
3. Freeze the output and pre-reveal review.
4. Reveal one named calibration target.
5. Compare, then retire the revealed target.
6. Invalidate the blind claim if sealed material was accessed.

## Run

Requires Python 3.10 or newer.

```sh
python3 -B sealed_eval.py examples/good.json
python3 -B sealed_eval.py --self-test
python3 -B -m unittest discover -s tests -v
```

Expected result for the good case:

```text
PASS sealed_evaluation good.json
```

The self-test proves that the good fixture passes and that examples with sealed
access, bad freeze order, a changed output, an unretired reveal, or a
calibration input fail with named finding codes.

## Case Contract

A case declares:

- sources and their `learning`, `calibration`, or `sealed` zones;
- the only source IDs authorized as generation input;
- one calibration target;
- a generated-output path and SHA-256 digest;
- timestamped access, freeze, review, and reveal events;
- revealed source IDs retired from future blind evaluation; and
- whether contamination was detected.

The checker hashes accessed learning and calibration files plus the generated
output. It deliberately does not open an unaccessed sealed file merely to prove
that it avoided opening it.

## What A Pass Establishes

For the supplied record and local files, a pass establishes that:

- generation inputs were declared in the learning zone;
- the output and pre-reveal review were frozen before calibration reveal;
- declared source access did not include sealed material or early calibration;
- accessed-file and output digests match;
- the named calibration target was revealed and retired; and
- the run is not declared contaminated.

## What It Does Not Establish

This is a relational checker, not a sandbox or an attestation system. It does
not prove that an access log is complete, authenticate timestamps or people,
prevent another process from reading sealed data, judge model quality, or make
a publication decision. Real evaluations still need operating-system or data
access controls and an independent review of the record.

## Public Data Notice

This repository contains synthetic fixtures only. Do not add manuscripts,
private datasets, personal notes, model transcripts, credentials, or real
holdout content to examples or issues.

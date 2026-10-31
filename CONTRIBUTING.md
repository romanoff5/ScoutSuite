# Contributing 

## Table of Contents
 * [Introduction](#introduction)
 * [Getting started](#getting-started)
 * [How to report a bug](#How-to-report-a-bug)
 * [How to suggest a new feature](#How-to-suggest-a-new-feature)
 * [Code review process](#Code-review-process)

## Introduction

These guidelines apply to independent development of this fork. The owner's task instructions define the scope; upstream contribution and reviewer requirements are not prerequisites for work here.

## Getting started

This fork is developed independently in `romanoff5/ScoutSuite`. Implement changes locally, validate them, then commit and push to the fork. Pull requests within the fork are optional unless requested. Do not create pull requests or push changes to `nccgroup/ScoutSuite`; upstream is a read-only reference.

1. Read `AGENTS.md` and the task's relevant modernization documents.
2. Inspect the existing code/tests and define the intended change before editing.
3. Create a focused branch:
    * Use `feat/descriptive-name` by default, or the branch requested for the task.
4. Implement your solution and the associated tests
5. Make sure your code follows the [PEP8 guidelines](https://www.python.org/dev/peps/pep-0008/)
6. Record test results, limitations and rollback instructions. Preserve unrelated workspace changes.
7. Commit and push the intended changes to `romanoff5/ScoutSuite`.
8. If a pull request is requested, create it only within the fork against the appropriate fork branch.
9. Integrate validated work into the fork's actual default branch, push and verify its remote SHA. Continue assigned batch tasks in dependency order without per-task sign-offs. Record genuine technical failures and keep defective features on a separate pushed branch.

## How to report a bug

When filing an issue, make sure to answer these five questions:

 1. What version of Python are you using?
 2. What operating system and processor architecture are you using?
 3. What did you do?
 4. What did you expect to see?
 5. What did you see instead?

## How to suggest a new feature

If you find yourself wishing for a feature that doesn't exist in Scout Suite, you are probably not alone. There are bound to be others out there with similar needs. Many of the features that Scout Suite has today have been added because our users saw the need. Open an issue on our issues list on GitHub which describes the feature you would like to see, why you need it, and how it should work.

## Code review process

Human review is optional for this solo-maintainer fork. No reviewer or upstream-approval gate applies. The owner authorizes local implementation, commit/push and integration of validated tasks into the fork's default branch; respect actual GitHub protection/rulesets without bypass. Offline tests, compatibility, limitations and rollback remain required. Assigned tasks may produce a fork-only release candidate after release gates pass; no upstream/PyPI release, live cloud assessment or stable-scanner replacement is authorized.

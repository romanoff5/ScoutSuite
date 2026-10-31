# M02-B action review — 2026-10-31

Only official `actions/*` JavaScript actions are used. Resolved the release tags
through the GitHub commits API, checked verified commit signatures, and reviewed
release notes and `action.yml` at those revisions. All three run on Node 24;
the supported hosted Windows 2022 / Ubuntu 24.04 runner families are selected
explicitly. Hosted runner image updates remain external, moving inputs.

| Action | Reviewed release | Immutable commit | Relevant behavior |
| --- | --- | --- | --- |
| [checkout](https://github.com/actions/checkout/releases/tag/v7.0.1) | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | Read-only checkout; credential persistence explicitly disabled; no PR-target event |
| [setup-python](https://github.com/actions/setup-python/releases/tag/v7.1.0) | v7.1.0 | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` | Exact x64 Python, no mirror token or implicit dependency installation/cache |
| [cache](https://github.com/actions/cache/releases/tag/v6.1.0) | v6.1.0 | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` | New cache service; pip downloads/wheels only; exact input hash key, no broad restore prefixes |

This is a scoped integration/source-manifest review, not an independent audit
of each action's bundled JavaScript or transitive npm dependencies. SHA pins
prevent tag movement; they do not establish an action is vulnerability-free.
Re-review release notes, signature, manifest and runner compatibility before
changing a pin. Never switch back to floating major-version tags.

`actionlint` is a separate tool, not a GitHub action. Version 1.7.12 release
binaries are acquired online and checked against the release API's SHA256
digests before extraction. Only the executable is extracted:

- Windows x64 zip: `6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9`
- Linux x64 tar.gz: `8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8`

See [official release files](https://github.com/rhysd/actionlint/releases/tag/v1.7.12).
The CI tool prints versioned commands. No third-party report, coverage or
assessment upload action remains; result evidence is in job logs/summaries.

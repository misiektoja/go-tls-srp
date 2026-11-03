# Release process

[RELEASE_NOTES.md](https://github.com/misiektoja/go-tls-srp/blob/main/RELEASE_NOTES.md) has one
section per version. Run the release check on `main`, then push a signed version tag:

```bash
VERSION=v0.1.0 make release-check
git tag -s v0.1.0 -m 'v0.1.0'
git push origin main v0.1.0
```

The release check exports `HEAD` with `git archive`, builds, vets and tests the export and imports it
from a separate module, which catches untracked and local-only files. With `VERSION` set it also
checks that `RELEASE_NOTES.md` has a section for the version and no Unreleased section.

Pushing a version tag starts the Release workflow. It can also be started by hand for an existing
tag. It:

1. refuses to rebuild a release that is already published,
2. checks that the tag is reachable from the default branch,
3. builds the release description from the section of `RELEASE_NOTES.md`,
4. repeats the release check on the tag,
5. generates a CycloneDX SBOM, complete source archives and SHA-256 checksums,
6. attests the build provenance of the artifacts,
7. creates a draft release with those assets.

Review the draft and publish it. Do not publish a release from the GitHub UI. Publishing creates the
tag, which starts the workflow. The workflow then refuses to rebuild the published release.

The documentation site is not part of a release. It is published from `main` whenever its sources
change.

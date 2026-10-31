# Docker Image

Build this fork from the repository root with `./docker/build.sh base`, or
`./docker/build.sh aws` for the AWS CLI wrapper. The local base image is
`scoutsuite-fork-base:local`; installation uses the checked-out fork source.

See [M02-A instructions and validation limits](../docs/modernization/M02_A_PACKAGING.md#docker-source-provenance)
before building. Docker execution has not yet been verified in this increment.
The [upstream wiki](https://github.com/nccgroup/ScoutSuite/wiki/Docker-Image)
describes historical upstream images, not this fork's current build procedure.

# Snakefoot

Post-Quantum Cryptography (PQC) certificate chain and CRL artifact generation. Powered by [liboqs](https://github.com/open-quantum-safe/liboqs)
and [pyasn1](https://github.com/russhousley/pyasn1-alt-modules).

# Quick start

Pull the latest Docker image:

`docker pull ghcr.io/cbonnell/snakefoot:latest`

Now you can proceed to the "Generating artifacts" and "Verifying artifacts" sections, specifying `ghcr.io/cbonnell/snakefoot:latest` as the image to run.

# Building the Docker image

Clone the repository:

`git clone https://github.com/CBonnell/snakefoot.git`

Build Docker image:

```bash
cd snakefoot
docker build . -t snakefoot:latest
```

Now you're ready to generate and verify artifacts.

*Note:* The Docker container uses the `/artifacts` volume to read and output artifacts. Examples are given below.

## Generating artifacts

`docker run -v $(pwd):/artifacts snakefoot:latest python generator.py /artifacts`

This command will generate artifacts and write them into a subdirectory named "artifacts" under the current working directory.

## Verifying artifacts

If you have a zip archive with the format described [here](https://github.com/IETF-Hackathon/pqc-certificates#zip-format-r2), then extract it. Alternatively, the artifacts produced by `generator.py` (as shown above) can be consumed directly.

Then run:

`docker run -v $(pwd):/artifacts snakefoot:latest`

The artifacts in the extracted "artifacts" directory will be verified.

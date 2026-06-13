#!/bin/sh

# analyze project
docker run --rm -v $PWD:/workspace -w /workspace \
  ghcr.io/oss-review-toolkit/ort analyze \
  --input-dir /workspace --output-dir /workspace/ort-result

# scan deoendencies
docker run --rm -v $PWD:/workspace -w /workspace \
  ghcr.io/oss-review-toolkit/ort scan \
  --ort-file /workspace/ort-result/analyzer-result.yml \
  --output-dir /workspace/ort-result

# write sbom
docker run --rm -v $PWD:/workspace -w /workspace \
  ghcr.io/oss-review-toolkit/ort report \
  -i /workspace/ort-result/scan-result.yml \
  --output-dir /workspace/ort-result \
  --report-formats CycloneDX,StaticHtml,WebApp

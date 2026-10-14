# Python runtime and dependencies for Anthropic's offline OSS Scanner audit.
# The scanner builds this image with network access, then audits it offline.
FROM python:3.12-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY . /src
WORKDIR /src

# Install WarrantKit and the project's declared test dependencies while
# network access is available during the image build.
RUN python -m pip install --upgrade pip \
    && python -m pip install ".[test]" \
    && python -m pip check

# Run portable tests during image preparation. Preserve the image even if a
# test currently fails so the scanner can still inspect and report on source.
RUN (python -m pytest -q -m "not integration" || echo "WARNING: WarrantKit tests reported failures; continuing so the scanner can inspect the project")

# Keep a useful interactive shell as the default for tools/check, while making
# the test command explicit and reproducible for maintainers.
CMD ["bash"]

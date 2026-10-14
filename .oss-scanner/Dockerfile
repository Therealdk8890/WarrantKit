# Build WarrantKit and its test dependencies while network access is available.
# The OSS Scanner runs the resulting image offline during its audit.
FROM python:3.12-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /src

# Copy the project source before installing so the editable install reflects
# the exact repository revision being scanned.
COPY . .

RUN python -m pip install --upgrade pip \
    && python -m pip install ".[test]" \
    && python -m pip check

# Run portable tests by default. Privileged Linux/cgroup integration proofs
# require host capabilities and are intentionally not claimed by this image.
CMD ["python", "-m", "pytest", "-q", "-m", "not integration"]

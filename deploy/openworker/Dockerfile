# syntax=docker/dockerfile:1.7

# The release workflow must pass an immutable Python base reference such as
# python:3.11.16-slim@sha256:<digest>. No mutable default is provided on purpose.
ARG PYTHON_BASE_IMAGE

FROM ${PYTHON_BASE_IMAGE} AS builder
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY python/requirements-openworker.lock.txt /tmp/requirements-openworker.lock.txt
RUN python -m pip install --upgrade pip \
    && python -m pip wheel --wheel-dir /wheelhouse -r /tmp/requirements-openworker.lock.txt

FROM ${PYTHON_BASE_IMAGE} AS runtime
ENV PYTHONPATH=/opt/mainstreet/python \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/mainstreet
COPY --from=builder /wheelhouse /wheelhouse
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheelhouse coworker==0.0.0 aisuite==0.1.14 \
    && python -m pip check \
    && rm -rf /wheelhouse
COPY python /opt/mainstreet/python
USER 65532:65532
ENTRYPOINT ["python", "-m", "mainstreet_runtimes.openworker_production_server"]
CMD ["--host", "0.0.0.0", "--port", "8080"]

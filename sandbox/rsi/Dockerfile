ARG PYTHON_IMAGE=python:3.11-slim
FROM ${PYTHON_IMAGE} AS tests
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
COPY backend/requirements-rsi.lock.txt /tmp/requirements-rsi.txt
RUN python -m pip install -r /tmp/requirements-rsi.txt
USER 65534:65534
WORKDIR /workspace

FROM tests AS runtime
USER root
RUN python -m pip install torch --index-url https://download.pytorch.org/whl/cpu \
    && python -m pip install 'sentence-transformers>=3,<6'
USER 65534:65534

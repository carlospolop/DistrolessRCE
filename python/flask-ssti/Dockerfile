#https://github.com/abdelino17/python-api
FROM python:3.10-slim AS base

# Setup env
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1

# Dependencies
FROM base AS python-deps

### Install pipenv and compilation dependencies
RUN pip install pipenv \
    && apt-get update \
    && apt-get install -y --no-install-recommends gcc

### Install python dependencies in /.venv
COPY Pipfile .
#COPY Pipfile.lock .
RUN PIPENV_VENV_IN_PROJECT=1 pipenv install --deploy

# Runtime
FROM gcr.io/distroless/python3

WORKDIR /app
COPY --from=python-deps /.venv/lib/python3.10/site-packages /app/site-packages
ENV PYTHONPATH /app/site-packages
COPY . .

EXPOSE 8080
ENTRYPOINT ["/usr/bin/python", "app.py"]
# Use a lightweight Python image
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    libpq-dev \
    postgresql-client \
    gcc \
    python3-dev \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install PDM globally
RUN pip install pdm

# TODO: we can split into a multi-stage build and just ship the .venv
# just keeping everything for now
COPY . .

# Ensure PDM always uses the in-project virtual environment
ENV PDM_VENV_IN_PROJECT=1
ENV PATH="/app/.venv/bin:$PATH"

# Install dependencies properly inside the virtual environment
RUN pdm install

# Expose the application port
# TODO: These should be configurable, not hard-coded and thus publishing them here is moot.
EXPOSE 8080
EXPOSE 5100

# Available CMDs
# See pyproject.toml for more details
# CMD ["pdm", "run", "aipserver"]
# CMD ["pdm", "run", "resolve"]
# CMD ["pdm", "run", "aiputil"]

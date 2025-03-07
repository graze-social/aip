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

# Ensure PDM always uses the in-project virtual environment
ENV PDM_VENV_IN_PROJECT=1
ENV PATH="/app/.venv/bin:$PATH"

# Copy only dependency files first (better caching)
COPY README.md LICENSE pyproject.toml pdm.lock ./

# Install dependencies properly inside the virtual environment
RUN pdm install

# Copy the rest of the project files (excluding `.venv`)
COPY . .

# Expose the application port
EXPOSE 8080
EXPOSE 5100

# Copy the entrypoint script and make it executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Use the entrypoint script to start the application
ENTRYPOINT ["/entrypoint.sh"]

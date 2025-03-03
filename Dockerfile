# Use a lightweight Python image
FROM python:3.12-slim

# Set environment variables
ENV EXTERNAL_HOSTNAME=grazeaip.tunn.dev \
    PLC_HOSTNAME=plc.bowfin-woodpecker.ts.net

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

# Install PDM
RUN pip install pdm

# Copy dependency files first for better caching
COPY . .
# COPY pyproject.toml pdm.lock LICENSE ./

# Create the virtual environment explicitly
RUN pdm venv create --force

# Install dependencies
RUN pdm install

# Verify packages are installed correctly
RUN pdm list

# Copy the rest of the application files

# Expose the application port
EXPOSE 8080

# Copy the new entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Use the entrypoint script to handle startup tasks
ENTRYPOINT ["/entrypoint.sh"]

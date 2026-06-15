FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# System deps: bash, git, jq (used in SBOM scanning)
RUN apt-get update && apt-get install -y \
    bash \
    git \
    jq \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Clone the repo
RUN git clone https://github.com/abluva-research/secure-agent-net.git /app

WORKDIR /app/malicious-package-scanner

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Run installer (no sudo needed since we're root in Docker)
RUN chmod +x install.sh && \
    bash install.sh /usr/local/lib/malicious-package-scanner /usr/local/bin

ENV PATH="/usr/local/bin:$PATH"

ENTRYPOINT ["mallscan"]
CMD ["--help"]

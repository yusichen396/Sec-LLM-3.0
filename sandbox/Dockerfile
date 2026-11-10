# Sec-LLM Agent Sandbox — isolated environment for security tool execution
FROM projectdiscovery/nuclei:v3.11.1 AS nuclei

FROM python:3.10-slim

# Install security tools
RUN sed -i -e 's/Components: main/Components: main non-free/' -e 's|URIs: http://|URIs: https://|' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    whatweb \
    ffuf \
    dnsutils \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN pip install --no-cache-dir \
    sqlmap \
    semgrep \
    bandit

COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei

# Create non-root user
RUN useradd -m -s /bin/bash sandbox
USER sandbox
WORKDIR /home/sandbox

# Default: print available tools
CMD ["sh", "-c", "echo 'Sandbox ready. Tools: nmap, sqlmap, nuclei, ffuf, nikto, whatweb, semgrep, bandit'"]

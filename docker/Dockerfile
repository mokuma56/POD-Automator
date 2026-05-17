FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openconnect \
    iproute2 \
    net-tools \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /pipeline
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ENV VMANAGE=198.18.133.10 \
    VMANAGE_USER=admin \
    VMANAGE_PASS=C1sco12345 \
    ROUTER_USER=admin \
    ROUTER_PASS=C1sco12345

COPY onboard.py onboard_router.py PseudocoBranches_Config-Group-Template.csv ./
COPY data/ ./data/

ENTRYPOINT ["python3", "onboard.py"]

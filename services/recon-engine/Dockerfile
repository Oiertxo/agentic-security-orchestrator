FROM python:3.12-slim

RUN apt update && apt install -y \
    ca-certificates \
    nmap dnsutils \
    && update-ca-certificates \
    && apt clean

COPY services/recon-engine/requirements.txt /opt/recon/requirements.txt

RUN pip install --no-cache-dir \
    --trusted-host pypi.org \
    --trusted-host files.pythonhosted.org \
    -r /opt/recon/requirements.txt

COPY services/recon-engine/app /opt/recon/app
WORKDIR /opt/recon/app

EXPOSE 5000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
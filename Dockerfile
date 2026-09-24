# PhishLens: one image for the api, worker and ui services (docker-compose.yml).
FROM python:3.11-slim

# libmagic (file type detection), zbar (QR codes), pango/cairo/harfbuzz (WeasyPrint PDF),
# yara (the yara-python wheel ships its own libyara; the CLI helps when writing rules).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libmagic1 libzbar0 \
        libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 libharfbuzz0b libcairo2 \
        fonts-dejavu-core shared-mime-info \
        yara \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MPLCONFIGDIR=/tmp/matplotlib

WORKDIR /app

# Dependencies first so code changes do not reinstall them.
COPY pyproject.toml README.md ./
RUN mkdir -p phishlens api ui && touch phishlens/__init__.py api/__init__.py ui/__init__.py \
    && pip install -e . && rm -rf phishlens api ui

COPY phishlens ./phishlens
COPY api ./api
COPY ui ./ui
COPY data ./data
COPY scripts ./scripts
COPY .streamlit ./.streamlit
RUN pip install --no-deps -e .

# MITRE ATT&CK names and tactics (optional; the rules file has a fallback table).
ARG FETCH_ATTACK_DATA=1
RUN if [ "$FETCH_ATTACK_DATA" = "1" ]; then \
        python scripts/update_attack_data.py || echo "ATT&CK download failed, using fallback"; \
    fi

# Runtime state lives in volumes, never in the image or a served folder.
RUN useradd --system --uid 10001 --home-dir /app phishlens \
    && mkdir -p /var/lib/phishlens /var/lib/phishlens-quarantine \
    && chown phishlens:phishlens /var/lib/phishlens /var/lib/phishlens-quarantine
ENV DATABASE_URL=sqlite:////var/lib/phishlens/phishlens.sqlite \
    REPORTS_DIR=/var/lib/phishlens/reports \
    DNS_CACHE_PATH=/var/lib/phishlens/dns_cache.sqlite \
    ENRICHMENT_CACHE_PATH=/var/lib/phishlens/enrichment_cache.sqlite \
    QUARANTINE_DIR=/var/lib/phishlens-quarantine
USER phishlens

EXPOSE 8000 8501
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]

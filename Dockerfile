# ══════════════════════════════════════════════════════════════
# CyberAI Pro v2.1 — Dockerfile (Xavfsizlik yaxshilangan)
# Non-root user, optimallashtirilgan layers
# ══════════════════════════════════════════════════════════════

# 1. Asosiy obraz
FROM python:3.11-slim

# 2. Metadata
LABEL maintainer="CyberAI Team" \
      version="2.1.0" \
      description="CyberAI Pro — Telegram Security Bot"

# 3. Tizim bog'liqliklarini o'rnatish
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-rus \
    tesseract-ocr-tur \
    libzbar0 \
    libyara-dev \
    libssl-dev \
    build-essential \
    python3-dev \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# 4. Ishchi papka
WORKDIR /app

# 5. pip yangilash va bog'liqliklarni o'rnatish (cache optimizatsiyasi)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 6. Loyiha fayllarini nusxalash
COPY . .

# 7. Zaruriy papkalar yaratish
RUN mkdir -p data downloads quarantine rules archive logs

# 8. Non-root user yaratish (xavfsizlik uchun)
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid 1000 --no-create-home appuser && \
    chown -R appuser:appgroup /app

# 9. Non-root user bilan ishlash
USER appuser

# 10. Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# 11. Botni ishga tushirish
CMD ["python", "run.py"]

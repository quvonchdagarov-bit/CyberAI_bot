# 1. Asosiy obraz (Image)
FROM python:3.11-slim

# 2. Tizim bog'liqliklarini o'rnatish (OCR, QR, YARA)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libzbar0 \
    libyara0 \
    libyara-dev \
    gcc \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 3. Ishchi papka (Working directory)
WORKDIR /app

# 4. Pip-ni yangilash va bog'liqliklarni o'rnatish
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 5. Loyiha fayllarini nusxalash
COPY . .

# 6. Zaruriy papkalarni yaratish va huquqlarni sozlash
RUN mkdir -p data downloads quarantine rules archive

# 7. Botni ishga tushirish
CMD ["python", "run.py"]

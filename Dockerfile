# مرحله اول: نصب Go نسخه 1.26 و کامپایل کردن فایل اجرایی
FROM golang:1.26 AS builder
WORKDIR /app
COPY . .
RUN go build -ldflags="-w -s" -o pantegnos ./cmd/pantegnos

# مرحله دوم: آماده‌سازی محیط پایتون و اجرای ربات
FROM python:3.10-slim
WORKDIR /app

# انتقال فایل اجرایی ساخته شده از مرحله قبل
COPY --from=builder /app/pantegnos /app/pantegnos

# کپی کردن سایر فایل‌ها (کدهای پایتون و دیتابیس)
COPY . .

# نصب کتابخانه‌های پایتون
RUN pip install --no-cache-dir -r requirements.txt

# دادن دسترسی ادمین برای اجرای فایل باینری
RUN chmod +x /app/pantegnos

# دستور نهایی برای روشن کردن ربات
CMD ["python", "main.py"]

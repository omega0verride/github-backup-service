FROM python:3.11-alpine

RUN apk add --no-cache git
# Added croniter for cron-style scheduling
RUN pip install github-backup croniter

WORKDIR /app
COPY main.py .
RUN mkdir /backups

CMD ["python", "-u", "main.py"]
FROM python:3.11-slim

WORKDIR /usr/src/app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y netcat-traditional bash && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY ./requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt && mkdir -p /docker-entrypoint

# Place entrypoint outside the application mount to avoid being overwritten by the bind mount
COPY ./entrypoint.sh /docker-entrypoint/entrypoint.sh
RUN sed -i 's/\r$//g' /docker-entrypoint/entrypoint.sh && chmod +x /docker-entrypoint/entrypoint.sh

# Copy the application code (this will be replaced by the host bind mount at runtime)
COPY . .

ENTRYPOINT ["/docker-entrypoint/entrypoint.sh"]

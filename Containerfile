FROM docker.io/library/python:3.12-slim@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r requirements.lock
COPY pyproject.toml /app/
COPY src /app/src
RUN pip install --no-deps --no-build-isolation . && useradd --uid 10001 --create-home hunter
COPY config.demo.yaml /app/config.demo.yaml
RUN mkdir -p /var/lib/soc-hunter && chown 10001:10001 /var/lib/soc-hunter
USER 10001:10001
ENTRYPOINT ["soc-hunter"]
CMD ["--help"]

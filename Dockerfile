FROM python:3.7
WORKDIR /app

RUN pip install gunicorn

ADD requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt
COPY app.py /app

EXPOSE 5000


ENV PYTHONUNBUFFERED=1
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--worker-class", "gthread", "--worker-tmp-dir", "/dev/shm", "--log-level", "DEBUG", "app:app"]

# add app info as environment variables
ARG GIT_COMMIT
ENV GIT_COMMIT $GIT_COMMIT
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP $BUILD_TIMESTAMP

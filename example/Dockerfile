FROM python:3.10

COPY ./requirements.txt /tmp/
# Expecting code to be mounted to `/app/src`
WORKDIR /app/src
RUN python -m pip install -U pip \
    && python -m pip install -r /tmp/requirements.txt \
    && rm -rf /tmp/requirements.txt
COPY ./docker-entrypoint.sh /bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
EXPOSE 8000

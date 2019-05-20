FROM debian:9.3
MAINTAINER peternguyen

RUN apt-get update
RUN apt-get install python python-pip -y
RUN pip install flask gunicorn pymongo

RUN mkdir /workdir

ADD web.py /workdir
ADD static /workdir/static
ADD templates /workdir/templates

WORKDIR /workdir

EXPOSE 5000

# start gunicorn
CMD ["/usr/local/bin/gunicorn", "-b", "0.0.0.0:5000", "web:app"]
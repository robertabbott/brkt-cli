FROM alpine:3.4
MAINTAINER Bracket Computing Inc.

RUN apk -U upgrade && \
    apk add --no-cache -U py-pip build-base libffi-dev openssl-dev python-dev ca-certificates curl

COPY . /brkt-cli
RUN pip install /brkt-cli
ENTRYPOINT ["brkt"]
CMD ["--help"]

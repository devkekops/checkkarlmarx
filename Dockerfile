FROM frolvlad/alpine-glibc

WORKDIR /app
COPY checkkarlmarx.py requirements.txt androidtemplate.html iostemplate.html ./

RUN apk update \
    && apk upgrade \
    && apk add --no-cache curl \
    && apk add --no-cache unzip \
    && apk add --no-cache openjdk8-jre

RUN apk add --no-cache python3 \
    && python3 -m ensurepip \
    && pip3 install --upgrade pip setuptools \
    && rm -r /usr/lib/python*/ensurepip && \
    if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
    if [[ ! -e /usr/bin/python ]]; then ln -sf /usr/bin/python3 /usr/bin/python; fi && \
    rm -r /root/.cache

RUN curl -L -o apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.5.0.jar && chmod +x apktool.jar

RUN curl -LO https://dl.google.com/android/repository/build-tools_r29.0.2-linux.zip \
    && unzip build-tools_r29.0.2-linux.zip -d build-tools \
    && rm -f build-tools_r29.0.2-linux.zip \
    && chmod +x build-tools/android-10/aapt

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "checkkarlmarx.py"]
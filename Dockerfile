FROM python:3

RUN apt-get update && \
    apt-get install -y astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

RUN mkdir /git
WORKDIR /git

RUN git clone -b main https://github.com/open-quantum-safe/liboqs.git
WORKDIR liboqs

RUN mkdir build && \
    cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_DIST_BUILD=ON .. && \
    ninja install

ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

WORKDIR /git
RUN git clone -b main https://github.com/open-quantum-safe/liboqs-python.git
WORKDIR liboqs-python

RUN python3 setup.py install

VOLUME /artifacts

WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./

CMD python3 verifier.py /artifacts

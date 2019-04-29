FROM continuumio/miniconda3

ADD environment.yml /tmp/environment.yml
RUN conda env create -f /tmp/environment.yml

RUN echo "activate 3rdparty_ca_flask" > ~/.bashrc
ENV PATH /opt/conda/envs/3rdparty_ca_flask/bin:$PATH

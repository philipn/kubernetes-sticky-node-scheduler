FROM ubuntu:14.04

RUN apt-get update && apt-get install -y python3-pip
RUN pip3 install pip --upgrade

COPY requirements.txt .
COPY scheduler.py .
RUN pip3 install -r requirements.txt

ENV NODE_FILTER_QUERY labelSelector=kubernetes.io/role=node

CMD ["python3", "scheduler.py"]

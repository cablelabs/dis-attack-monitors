# Use an official Python runtime as a parent image
FROM python:3.6-slim

WORKDIR /app

COPY requirements.txt dis-arbor-monitor.py ./
COPY dis_client_sdk/ ./dis_client_sdk/

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

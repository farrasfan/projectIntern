FROM python:3.9-slim

RUN apt-get update && apt-get upgrade -y && apt-get clean

RUN pip install --upgrade pip

WORKDIR /app

COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /app/configs && chmod -R a+rwx /app/configs

COPY app/ .

# Expose port Flask
EXPOSE 5000

ENV FLASK_APP=main.py

CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
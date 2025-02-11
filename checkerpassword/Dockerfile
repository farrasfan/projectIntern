# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Update and upgrade the system packages
RUN apt-get update && apt-get upgrade -y && apt-get clean

# Upgrade pip
RUN pip install --upgrade pip

# Set working directory inside the container
WORKDIR /app

# Copy only the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project files into the container
COPY app/ .

# Expose port 5000 for Flask application
EXPOSE 5001

ENV FLASK_APP=main.py

# Use gunicorn instead of flask run for production
CMD ["flask", "run", "--host=0.0.0.0", "--port=5001"]

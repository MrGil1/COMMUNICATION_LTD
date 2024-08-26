FROM python:3.10.10

# Set the working directory in the container to /app
WORKDIR /app
ADD . /app

COPY .env .env

RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x backend.py

EXPOSE 5678
EXPOSE 8000



CMD ["python", "backend.py"]
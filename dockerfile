FROM python:3.10-slim

WORKDIR /app

COPY . /app

ENV PYTHONPATH=/app

# ENV JWT_SECRET_KEY=d140e79c441345eb9eeef07d753cdc28
# ENV MONGODB_PASSWORD=Qcd8InOMIGCUwYCK
# ENV MONGODB_USERNAME=phishAdmin

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENV FLASK_APP=PhishGuard.__init__

CMD ["flask", "run", "--host=0.0.0.0"]

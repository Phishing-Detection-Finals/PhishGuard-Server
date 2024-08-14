FROM python:3.10-slim

WORKDIR /app

COPY . /app

ENV PYTHONPATH=/app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENV FLASK_APP=PhishGuard.__init__

CMD ["flask", "run", "--host=0.0.0.0"]

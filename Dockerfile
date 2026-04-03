FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY a2a_redis.py example_agent.py ./

CMD ["python3", "example_agent.py"]

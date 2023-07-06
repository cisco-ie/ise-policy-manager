FROM python:3.8
WORKDIR /app
COPY ./app ./app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
#CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9090"]
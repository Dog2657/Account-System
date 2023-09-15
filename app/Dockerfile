From python:3.10

Run apt-get -y update

Copy requirements.txt .

Run pip install -r ./requirements.txt

Expose 80

Add . .

WorkDIR ./app/src

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port","80"]
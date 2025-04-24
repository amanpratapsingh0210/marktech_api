# marktech_api

# Setup

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python app.py`
4. The API will be available at `http://localhost:5000`

# Testing the API

You can use tools like Postman or cURL to test the API endpoints.

# Example Requests:

1. Register a new user:

curl -X POST -H "Content-Type: application/json" -d '{"username":"testuser","password":"testpass"}' http://localhost:5000/register

2. Login and get token:

curl -X POST -H "Content-Type: application/json" -d '{"username":"testuser","password":"testpass"}' http://localhost:5000/login

3. Create a task (use token fron your login):

curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer YOUR_TOKEN" -d '{"title":"My first task"}' http://localhost:5000/tasks

4. Get all Tasks:

curl -X GET -H "Authorization: Bearer YOUR_TOKEN" http://localhost:5000/tasks
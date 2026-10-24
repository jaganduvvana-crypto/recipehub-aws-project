# RecipeHub - AWS Recipe Sharing Platform

## Project Overview
RecipeHub is a cloud-based recipe sharing website built using Python Flask and AWS services.

## Features
- User registration and login
- Add and share recipes
- Upload recipe images
- Rate recipes
- Store data in MySQL
- Health check for database connectivity

## AWS Services
- Amazon EC2: Hosts the web application
- Amazon RDS for MySQL: Stores application data
- Amazon S3: Stores recipe images
- Amazon Cognito: User authentication
- Amazon VPC: Network isolation
- Security Groups: Network access control

## Technologies
- Python and Flask
- HTML and CSS
- MySQL
- Boto3
- PyMySQL
- python-dotenv
- Git and GitHub

## Project Files
- app.py: Flask application
- requirements.txt: Python dependencies
- templates/: HTML pages
- static/: Static website files
- .gitignore: Excludes secrets and temporary files

## Setup
1. Install Python.
2. Create and activate a virtual environment.
3. Install packages using pip install -r requirements.txt.
4. Configure required environment variables in a local .env file.
5. Configure the required AWS resources and permissions.
6. Run the application using python app.py.

## Security
Never upload .env files, passwords, access keys, or other secrets to GitHub.

## Author
Jagan

## Purpose
Educational project developed using AWS Academy Learner Lab.

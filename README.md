# PhishGuard-Server

Welcome to [PhishGuard-Server](https://github.com/Phishing-Detection-Finals/PhishGuard-Server)! This is a brief guide to help you get started with the project.

## Prerequisites

Make sure you have Python installed on your system. You can download it from [python.org](https://www.python.org/).

## Setup Virtual Environment

It's recommended to use a virtual environment to manage project dependencies. To create a virtual environment, run the following commands in your terminal:

### Navigate to project directory

```bash
cd path/to/project/directory
```

### Create virtual environment

```bash
python -m venv venv
```

## Activate Virtual Environment

Activate the virtual environment by running the appropriate command based on your operating system:

- **Windows**:

```bash
venv\Scripts\activate
```
- **Linux/macOS**:

```bash
source venv/bin/activate
```  

## Install Requirements file

Install project dependencies by running:

```bash
pip install -r requirements.txt
```

## Set Environment Variables

Create a '.env' file in the root directory of the project and add the following variables:

```bash
JWT_SECRET_KEY=your_jwt_secret_key_here
MONGODB_USERNAME=your_mongodb_user_access_username
MONGODB_PASSWORD=your_mongodb_user_access_password
```

## Running the Application

To run the application, use the following command:

```bash
python -m PhishGuard.__init__
```

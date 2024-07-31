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

## Endpoints

### Authentication Routes

1. Signup
   - **Description:** Endpoint to register a new user.
   - **Method:** POST
   - **URL:** `/auth/signup`
   - **Request Body:**
     - `username`: User's username (string)
     - `email`: User's email (string)
     - `password`: User's password (string)
   - **Response:**
     - Success message (string) (might change)

2. Login
   - **Description:** Endpoint to authenticate users and generate JWT tokens.
   - **Method:** POST
   - **URL:** `/auth/login`
   - **Request Body:**
     - `email`: User's email (string)
     - `password`: User's password (string)
   - **Response:**
     - `access_token`: JWT access token for authenticated user (string)
     - `refresh_token`: JWT refresh token for authenticated user (string)

3. Refresh Access Token
   - **Description:** Endpoint to refresh JWT access token.
   - **Method:** POST
   - **URL:** `/auth/refresh`
   - **Authorization Header:** JWT refresh token in the format `Bearer <refresh_token>`
   - **Response:**
     - `access_token`: Refreshed JWT access token for authenticated user (string)

### User Setting Routes

1. Delete User
   - **Description:** Endpoint to delete user account.
   - **Method:** DELETE
   - **URL:** `/setting/user`
   - **Authorization Header:** JWT access token in the format `Bearer <access_token>`
   - **Response:** Success message (string)

2. Update Username
   - **Description:** Endpoint to update user's username.
   - **Method:** PUT
   - **URL:** `/setting/user/username`
   - **Authorization Header:** JWT access token in the format `Bearer <access_token>`
   - **Request Body:**
     - `username`: New username (string)
   - **Response:** Success message (string)

3. Update Email
   - **Description:** Endpoint to update user's email.
   - **Method:** PUT
   - **URL:** `/setting/user/email`
   - **Authorization Header:** JWT access token in the format `Bearer <access_token>`
   - **Request Body:**
     - `email`: New email (string)
   - **Response:**
      - access_token: New JWT access token for the authenticated user (string)
      - refresh_token: New JWT refresh token for the authenticated user (string)

4. Update Password
   - **Description:** Endpoint to update user's password.
   - **Method:** PUT
   - **URL:** `/setting/user/password`
   - **Authorization Header:** JWT access token in the format `Bearer <access_token>`
   - **Request Body:**
     - `password`: New password (string)
   - **Response:** Success message (string)

5. Get User Details
   - **Description:** Endpoint to get user details.
   - **Method:** GET
   - **URL:** `/setting/user`
   - **Authorization Header:** JWT access token in the format `Bearer <access_token>`
   - **Response:** User details (JSON object)
   - 
   

6. Update User Settings
- **Description:** Endpoint to update user settings. You can update username, email, and/or password in a single request.
- **Method:** PATCH
- **URL:** `/setting/user`
- **Authorization Header:** JWT access token in the format `Bearer <access_token>`
- **Request Body:**
   - `username`: New username (string, optional),
   - `email`: New email (string, optional),
   - `password`: New password (string, optional)
- **Response:**  Success message (string)



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
## Test Coverage Report
============================= test session starts ==============================
platform linux -- Python 3.10.14, pytest-8.2.0, pluggy-1.5.0
rootdir: /home/runner/work/PhishGuard-Server/PhishGuard-Server
plugins: cov-5.0.0
collected 28 items

PhishGuard/test/user_auth_test.py ...                                    [ 10%]
PhishGuard/test/user_data_validation_test.py ....................        [ 82%]
PhishGuard/test/user_setting_test.py .....                               [100%]

---------- coverage: platform linux, python 3.10.14-final-0 ----------
Name                                                         Stmts   Miss  Cover
--------------------------------------------------------------------------------
PhishGuard/__init__.py                                          45     11    76%
PhishGuard/src/__init__.py                                       0      0   100%
PhishGuard/src/constants.py                                     17      0   100%
PhishGuard/src/controllers/authentication_controller.py         53      7    87%
PhishGuard/src/controllers/user_setting_controller.py           85     17    80%
PhishGuard/src/dal/user_crud.py                                 50      4    92%
PhishGuard/src/data/user.py                                     20      0   100%
PhishGuard/src/db/phishguard_db_connection.py                   16      1    94%
PhishGuard/src/exceptions/offensive_username_exception.py        3      1    67%
PhishGuard/src/exceptions/password_strength_exception.py         3      0   100%
PhishGuard/src/exceptions/previous_user_data_exception.py        4      0   100%
PhishGuard/src/exceptions/user_already_exists_exception.py       3      0   100%
PhishGuard/src/exceptions/user_not_exists_exception.py           3      0   100%
PhishGuard/src/exceptions/username_not_valid_exception.py        3      0   100%
PhishGuard/src/exceptions/wrong_password_exception.py            3      0   100%
PhishGuard/src/services/user_service.py                         54      0   100%
PhishGuard/src/user_param_enum.py                                5      0   100%
PhishGuard/src/utils/jwt_utils.py                               16      1    94%
PhishGuard/src/utils/user_utils.py                              39      0   100%
PhishGuard/src/validator.py                                     30      0   100%
PhishGuard/test/__init__.py                                      0      0   100%
PhishGuard/test/test_constants.py                               41      0   100%
PhishGuard/test/user_auth_test.py                               44      0   100%
PhishGuard/test/user_data_validation_test.py                    32      0   100%
PhishGuard/test/user_setting_test.py                            85      0   100%
PhishGuard/test/user_test_utils.py                              49      0   100%
--------------------------------------------------------------------------------
TOTAL                                                          703     42    94%


======================== 28 passed in 141.70s (0:02:21) ========================

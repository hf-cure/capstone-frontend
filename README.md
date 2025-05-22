# Capstone Frontend

A Flask-based frontend application for secure password validation using Private Set Intersection (PSI).

## Prerequisites

Before setting up this project, make sure you have **Python** installed on your system.

- **Python 3.8 or higher** is recommended
- You can download Python from [python.org](https://www.python.org/downloads/)

## Project Setup

### 1. Clone the Repository

```bash
git clone https://github.com/hf-cure/capstone-frontend.git
cd capstone-frontend
```

### 2. Navigate to Project Directory

Open your terminal and navigate to the directory where you cloned the project. Make sure you are in the same directory where `app.py` is located.

```bash
# Verify you're in the correct directory
ls app.py
```

### 3. Run the Application

```bash
python app.py
```

## Application Details

- **Port**: The application runs on the default port `5000`
- **Initial URL**: http://127.0.0.1:5000/
- **Signup URL**: http://127.0.0.1:5000/signup

## How to Use

1. Navigate to http://127.0.0.1:5000/signup
2. Create a new account
3. Login to system using the same credentials as signup
4. Add password details including:
   - Website name
   - Username
   - Password
5. Click "Add Password"
6. The system will validate your password against a secure database using Private Set Intersection
7. View the validation results

## Application Flow

The frontend communicates with the backend API to perform secure password validation:

1. User creates an account through the signup page
2. User adds password information for various websites
3. When "Add Password" is clicked, the frontend calls the backend API
4. The backend uses PSI (Private Set Intersection) with OpenMined to check if the password exists in the database
5. Results are returned to the frontend and displayed to the user

## Backend Integration

This frontend works in conjunction with the backend service running on port 8000. Make sure the backend is running before using the frontend application.

## Troubleshooting

- Ensure Python is properly installed and accessible from your command line
- Verify you're in the correct directory (where app.py is located)
- Make sure the backend service is running on port 8000
- Check that no other application is using port 5000

## Repository

Frontend Repository: https://github.com/hf-cure/capstone-frontend
Backend Repository: https://github.com/hf-cure/capstone

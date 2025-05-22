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
   <img width="1512" alt="Screenshot 2025-05-22 at 2 07 38 pm" src="https://github.com/user-attachments/assets/a029f69d-c8ba-4b42-a4f1-f0ba1e2c0c5c" />

3. Create a new account
4. Login to system using the same credentials as signup
<img width="1512" alt="Screenshot 2025-05-22 at 2 05 34 pm" src="https://github.com/user-attachments/assets/cd349acf-3b85-40b1-b5a1-25bd8ae9bc78" />

5. Add password details including:
   - Website name
   - Username
   - Password

<img width="1506" alt="Screenshot 2025-05-22 at 2 08 29 pm" src="https://github.com/user-attachments/assets/519d7bf9-9098-4501-9ee1-80d713f3e6fc" />

6. Click "Add Password"
7. The system will validate your password against a secure database using Private Set Intersection
8. View the validation results
<img width="1507" alt="Screenshot 2025-05-22 at 2 08 48 pm" src="https://github.com/user-attachments/assets/34c148be-85d3-488a-95d8-0d860e941f77" />
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

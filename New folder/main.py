from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from passlib.hash import bcrypt
import mysql.connector


app = FastAPI()

# MySQL connection setup
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",  
        password="root",  
        database="fastapi_login"  
    )

# Pydantic models
class SignupModel(BaseModel):
    name: str
    email: str 
    mobile_number: str  
    password: str

class LoginModel(BaseModel):
    email: str  
    password: str

# Root endpoint
@app.get("/")
def read_root():
    return {"message": "Welcome to FastAPI_LOGIN!"}

# Signup route
@app.post("/signup")
def signup(user: SignupModel):
    hashed_password = bcrypt.hash(user.password)
    db = get_db_connection()
    cursor = db.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (name, email, mobile_number, password) VALUES (%s, %s, %s, %s)",
            (user.name, user.email, user.mobile_number, hashed_password)
        )
        db.commit()
    except mysql.connector.IntegrityError:
        db.rollback()  # Rollback transaction if there's an error
        raise HTTPException(status_code=400, detail="Email already exists")
    finally:
        cursor.close()
        db.close()

    return {"message": "User created successfully"}

# Login route
@app.post("/login")
def login(user: LoginModel):
    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute("SELECT password FROM users WHERE email = %s", (user.email,))
    result = cursor.fetchone()

    cursor.close()
    db.close()

    if result is None or not bcrypt.verify(user.password, result[0]):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    
    return {"message": "Login successful"}

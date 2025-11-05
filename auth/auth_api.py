from fastapi import FastAPI, Request
from pydantic import BaseModel
import psycopg2
import streamlit as st
import bcrypt
from fastapi.responses import JSONResponse
from hasher import Hasher
from utils import generate_random_pw

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded


FIELD_VS_INDEXES = {
    "email": 2,
    "name": 3
}

@st.cache_resource
def init_connection():
    return psycopg2.connect(**st.secrets["postgres"])


def run_query_update(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
        conn.commit()
        

def run_query_select(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
        return cur.fetchall()


class Input_check_credentials(BaseModel):
    username : str

class Output_check_credentials(BaseModel):
    username : str
    name : str

class Input_check_password(BaseModel):
    username : str
    password : str

class Input_register(BaseModel):
    username : str
    password : str
    email : str
    name : str

class Output_forgot_password(BaseModel):
    username : str
    email : str
    password : str

class Input_forgot_username(BaseModel):
    email : str

class Output_forgot_username(BaseModel):
    username : str
    email : str

class Input_update_details(BaseModel):
    username : str
    field : str
    value : str


def get_limiter_id(request: Request) -> str:
    """
    Limiter ID
    """
    try:
        username = request._json["username"]
    except Exception as e:
        username = "testusername"

    return username


def get_limiter_email(request: Request) -> str:
    """
    Limiter email
    """
    try:
        email = request._json["email"]
    except Exception as e:
        email = "test@test.com"

    return email


app = FastAPI()
conn = init_connection()
limiter = Limiter(key_func=get_remote_address, default_limits=["5/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    

@app.post("/check_credentials")
@limiter.limit("3/minute", key_func=get_limiter_id)
@limiter.limit("5/minute", key_func=get_remote_address)
def check_credentials(request : Request, input : Input_check_credentials) -> Output_check_credentials:
  

    user_found = None
    name_found = None

    try:
        rows = run_query_select(conn, f"SELECT * from users WHERE users.username = '{input.username}';")
        if len(rows) == 1:
            for row in rows:
                user_found = row[0]
                name_found = row[3]
    except Exception as e:
        st.error(e)

    if user_found:
        return JSONResponse(status_code=200, content={"username": user_found, "name": name_found})
    else:
        return JSONResponse(status_code=401, content={"message": "Invalid username"})


@app.post("/check_password")
@limiter.limit("3/minute", key_func=get_limiter_id)
@limiter.limit("5/minute", key_func=get_remote_address)
def check_password(request : Request, input : Input_check_password):

    pass_found = None

    try:
        rows = run_query_select(conn, f"SELECT * from users WHERE users.username = '{input.username}';")
        if len(rows) == 1:
            for row in rows:
                pass_found = row[1]
    except Exception as e:
        st.error(e)

    if bcrypt.checkpw(input.password.encode(), pass_found.encode()):
        return JSONResponse(status_code=200, content={"message": "OK"})
    else:
        return JSONResponse(status_code=401, content={"message": "Invalid password"})


@app.post("/reset_password")
@limiter.limit("3/minute", key_func=get_limiter_id)
@limiter.limit("5/minute", key_func=get_remote_address)
def reset_password(request : Request, input : Input_check_password):

    pass_hash = Hasher([input.password]).generate()[0]

    try:
        run_query_update(conn, f"UPDATE users SET password = '{pass_hash}' WHERE username = '{input.username}';")
    except Exception as e:
        st.error(e)
        return JSONResponse(status_code=401, content={"message": "Error by reseting the password"})
    
    return JSONResponse(status_code=200, content={"message": "OK"})

@app.post("/register")
@limiter.limit("3/minute", key_func=get_limiter_id)
@limiter.limit("5/minute", key_func=get_remote_address)
def register(request : Request, input : Input_register):

    user_found = None

    try:
        rows = run_query_select(conn, f"SELECT * from users WHERE users.username = '{input.username}';")
        if len(rows) >= 1:
            for row in rows:
                user_found = row[0]
    except Exception as e:
        st.error(e)

    if not user_found:
        email_found = None
        try:
            rows = run_query_select(conn, f"SELECT * from users WHERE users.email = '{input.email}';")
            if len(rows) >= 1:
                for row in rows:
                    email_found = row[2]
        except Exception as e:
            st.error(e)

        if not email_found:
            pass_hash = Hasher([input.password]).generate()[0]

            try:
                run_query_update(conn, f"INSERT INTO users (username, password, email, name) VALUES ('{input.username}', '{pass_hash}', '{input.email}', '{input.name}');")
            except Exception as e:
                st.error(e)
                return JSONResponse(status_code=400, content={"message": "Error by registering the user"})

            return JSONResponse(status_code=200, content={"message": "OK"})
        else:
            return JSONResponse(status_code=400, content={"message": "Email already taken"})
    else:
        return JSONResponse(status_code=400, content={"message": "Username already taken"})


@app.post("/forgot_password")
@limiter.limit("3/minute", key_func=get_limiter_id)
@limiter.limit("5/minute", key_func=get_remote_address)
def forgot_password(request : Request, input : Input_check_credentials) -> Output_forgot_password:

    user_found = None
    email_found = None

    try:
        rows = run_query_select(conn, f"SELECT * from users WHERE users.username = '{input.username}';")
        if len(rows) == 1:
            for row in rows:
                user_found = row[0]
                email_found = row[2]
    except Exception as e:
        st.error(e)

    if user_found:
        random_password = generate_random_pw()
        pass_hash = Hasher([random_password]).generate()[0]

        try:
            run_query_update(conn, f"UPDATE users SET password = '{pass_hash}' WHERE username = '{user_found}';")
        except Exception as e:
            st.error(e)
            return JSONResponse(status_code=400, content={"message": "Error by updating the password"})
       
        return JSONResponse(status_code=200, content={"username": user_found, "email": email_found, "password": random_password})
    else:
        return JSONResponse(status_code=401, content={"message": "Invalid username"})    


@app.post("/forgot_username")
@limiter.limit("3/minute", key_func=get_limiter_email)
@limiter.limit("5/minute", key_func=get_remote_address)
def forgot_username(request : Request, input : Input_forgot_username) -> Output_forgot_username:

    user_found = None

    try:
        rows = run_query_select(conn, f"SELECT * from users WHERE users.email = '{input.email}';")
        if len(rows) == 1:
            for row in rows:
                user_found = row[0]
    except Exception as e:
        st.error(e)

    if user_found:
        return JSONResponse(status_code=200, content={"username": user_found, "email": input.email})
    else:
        return JSONResponse(status_code=401, content={"message": "Invalid email"})


@app.post("/update_details")
@limiter.limit("3/minute", key_func=get_limiter_id)
@limiter.limit("5/minute", key_func=get_remote_address)
def update_details(request : Request, input : Input_update_details):

    user_found = None
    field_found = None

    try:
        rows = run_query_select(conn, f"SELECT * from users WHERE users.username = '{input.username}';")
        if len(rows) == 1:
            for row in rows:
                user_found = row[0]
                field_found = row[FIELD_VS_INDEXES[input.field]]
    except Exception as e:
        st.error(e)

    if not user_found:
        return JSONResponse(status_code=400, content={"message": "Invalid username"})

    if input.field == "email":
        email_found = None
        try:
            rows = run_query_select(conn, f"SELECT * from users WHERE users.email = '{input.value}' AND users.username != '{user_found}';")
            if len(rows) >= 1:
                for row in rows:
                    email_found = row[2]
        except Exception as e:
            st.error(e)

        if email_found:
            return JSONResponse(status_code=400, content={"message": "Email already taken"})

    if input.value != field_found:
        try:
            run_query_update(conn, f"UPDATE users SET {input.field} = '{input.value}' WHERE username = '{user_found}';")
        except Exception as e:
            st.error(e)
            return JSONResponse(status_code=400, content={"message": "Error by updating the details"})
       
        return JSONResponse(status_code=200, content={"message": "OK"})
    else:
        return JSONResponse(status_code=400, content={"message": "New and current values are the same"})

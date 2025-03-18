from fastapi import FastAPI, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import mysql.connector
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import bcrypt
import os
from datetime import datetime

app = FastAPI()
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
# Please use your directory while running.
MODEL_DIRECTORY = r"C:\Users\Abumuzzammil\Desktop\petition_classifier_project\backend\model"
tokenizer = None
model = None

def load_model():
    global tokenizer, model
    if tokenizer is None or model is None:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_DIRECTORY)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIRECTORY)
table_map = {
    "Public Works Department": "pwd_petitions",
    "Finance Department": "finance_petitions",
    "Education Department": "education_petitions"
}
department_tables = {
    "Public Works Department": "petitions_pwd",
    "Finance Department": "petitions_finance",
    "Education Department": "petitions_education"
}
def connect_to_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="aph",
        port=3306
    )


@app.get("/")
def index():
    return {"message": "API up and running. Model loaded."}
def simple_rule_classifier(text):
    text = text.lower()
    if any(term in text for term in ["budget", "finance", "fund", "loan", "startup", "tax"]):
        return "Finance Department"
    if any(term in text for term in ["teacher", "student", "college", "university", "school", "library"]):
        return "Education Department"
    if any(term in text for term in [
        "bridge", "road", "pipeline", "building", "stormwater", "drainage",
        "maintenance", "borewell", "repair", "sewage", "infrastructure", "public toilet"
    ]):
        return "Public Works Department"
    return None

@app.post("/register")
def register_account(
    full_name: str = Form(...),
    new_user: str = Form(...),
    new_pass: str = Form(...)
):
    db = connect_to_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (new_user,))
    if cur.fetchone():
        return {"error": "Username is already taken"}

    hashed_password = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
    cur.execute("INSERT INTO users (name, username, password) VALUES (%s, %s, %s)", (full_name, new_user, hashed_password))
    db.commit()
    cur.close()
    db.close()
    return {"message": "User registered successfully"}

@app.post("/login")
def login_user(user_id: str = Form(...), passcode: str = Form(...)):
    predefined_admins = {
        "pwd": {"password": "123", "dashboard": "admindashboardaph.html", "department": "Public Works Department"},
        "fin": {"password": "123", "dashboard": "admindashboardaph.html", "department": "Finance Department"},
        "edu": {"password": "123", "dashboard": "admindashboardaph.html", "department": "Education Department"},
    }
    if user_id in predefined_admins and predefined_admins[user_id]["password"] == passcode:
        return {
            "message": "Admin login successful",
            "role": "admin",
            "dashboard": predefined_admins[user_id]["dashboard"],
            "department": predefined_admins[user_id]["department"]
        }
    db = connect_to_db()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE username = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    db.close()

    if user and bcrypt.checkpw(passcode.encode(), user["password"].encode()):
        return {
            "message": "User login successful",
            "role": "user",
            "dashboard": "dashboardaph.html"
        }

    return {"error": "Invalid login credentials"}
@app.post("/classify")
def predict_category(petition_text: str = Form(...)):
    guessed = simple_rule_classifier(petition_text)
    if guessed:
        return {"category": guessed}

    load_model()
    inputs = tokenizer(petition_text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        logits = model(**inputs).logits
    result = torch.argmax(logits, dim=1).item()
    return {"category": table_map.get(result, "Unknown")}
@app.post("/submit_to_department")

def save_petition(
    name: str = Form(...),
    phone: str = Form(...),
    address: str = Form(...),
    petition_type: str = Form(...),
    petition_subject: str = Form(...),
    petition_description: str = Form(...),
    category: str = Form(...),
    petition_file: UploadFile = File(None)
):
    try:
        table = department_tables.get(category)
        if not table:
            return {"error": "Invalid category provided"}

        file_name = None
        if petition_file:
            upload_path = "uploads"
            os.makedirs(upload_path, exist_ok=True)
            file_name = datetime.now().strftime("%Y%m%d%H%M%S_") + petition_file.filename
            with open(os.path.join(upload_path, file_name), "wb") as f:
                f.write(petition_file.file.read())
        conn = connect_to_db()
        cursor = conn.cursor()
        insert_query = f"""
            INSERT INTO {table}
            (name, phone, address, petition_type, petition_subject, petition_description, petition_file, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (name, phone, address, petition_type, petition_subject, petition_description, file_name, "Pending")
        cursor.execute(insert_query, values)
        conn.commit()
        cursor.close()
        conn.close()

        return {"message": "Petition recorded successfully", "department": category}
    except mysql.connector.Error as db_err:
        return {"error": f"Database error: {db_err}"}
    except OSError as os_err:
        return {"error": f"File system error: {os_err}"}
    except Exception as ex:
        return {"error": f"An unexpected error occurred: {ex}"}

@app.get("/admin/petitions")
def list_petitions(department: str):
    table = department_tables.get(department)
    if not table:
        return {"error": "Invalid department requested"}
    db = connect_to_db()
    cur = db.cursor(dictionary=True)
    cur.execute(f"SELECT * FROM {table}")
    result = cur.fetchall()
    cur.close()
    db.close()
    return result

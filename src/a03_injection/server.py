"""
A03 - Injection (Vulnerable Implementation)
Demonstrates SQL Injection vulnerabilities
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
import sqlite3
import os
from typing import Dict, Any, Optional
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="A03 - Injection (Vulnerable)", version="1.0.0")

# Database setup
DB_PATH = "vulnerable_app.db"

class UserLogin(BaseModel):
    username: str
    password: str

class ProductSearch(BaseModel):
    category: Optional[str] = None
    name: Optional[str] = None

def init_db():
    """Initialize database with sample data"""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT
        )
    """)
    
    # Create products table
    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            category TEXT,
            price REAL,
            description TEXT
        )
    """)
    
    # Insert sample users
    users = [
        (1, 'admin', 'admin123', 'admin@company.com', 'admin'),
        (2, 'alice', 'alice123', 'alice@company.com', 'user'),
        (3, 'bob', 'bob456', 'bob@company.com', 'user'),
        (4, 'charlie', 'charlie789', 'charlie@company.com', 'user')
    ]
    
    cursor.executemany(
        "INSERT INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)",
        users
    )
    
    # Insert sample products
    products = [
        (1, 'Laptop', 'electronics', 999.99, 'High-performance laptop'),
        (2, 'Phone', 'electronics', 599.99, 'Smartphone with great camera'),
        (3, 'Book', 'books', 29.99, 'Programming guide'),
        (4, 'Headphones', 'electronics', 199.99, 'Noise-canceling headphones'),
        (5, 'Tablet', 'electronics', 399.99, 'Portable tablet device')
    ]
    
    cursor.executemany(
        "INSERT INTO products (id, name, category, price, description) VALUES (?, ?, ?, ?, ?)",
        products
    )
    
    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(index_path, media_type="text/html")

@app.get("/")
async def root():
    return {
        "mensagem": "A03 - Injection (Implementacao Vulneravel)", 
        "endpoints": ["/login", "/search", "/users"]
    }

@app.post("/login")
async def login(user_data: UserLogin):
    """
    🚨 VULNERABLE: SQL Injection in login
    Attacker can bypass authentication with: ' OR '1'='1' --
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 🚨 VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{user_data.username}' AND password = '{user_data.password}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                "success": True,
                "message": "Login successful",
                "user": {
                    "id": user[0],
                    "username": user[1],
                    "email": user[3],
                    "role": user[4]
                },
                "query_executed": query  # For educational purposes
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    
    except Exception as e:
        conn.close()
        return {"error": str(e), "query_executed": query}

@app.get("/search")
async def search_products(category: str = None, name: str = None):
    """
    🚨 VULNERABLE: SQL Injection in search
    Attacker can extract data with: electronics' UNION SELECT username, password, email, role, 'injected' FROM users --
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Build base query
    query = "SELECT * FROM products WHERE 1=1"
    
    # 🚨 VULNERABLE: Direct string concatenation
    if category:
        query += f" AND category = '{category}'"
    
    if name:
        query += f" AND name LIKE '%{name}%'"
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        products = []
        for row in results:
            products.append({
                "id": row[0],
                "name": row[1],
                "category": row[2],
                "price": row[3],
                "description": row[4]
            })
        
        return {
            "products": products,
            "query_executed": query  # For educational purposes
        }
    
    except Exception as e:
        conn.close()
        return {"error": str(e), "query_executed": query}

@app.get("/users")
async def get_users(limit: int = 10):
    """
    🚨 VULNERABLE: SQL Injection in limit parameter
    Attacker can dump all data with: 1; INSERT INTO users (username, password) VALUES ('hacker', 'hacked'); --
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 🚨 VULNERABLE: Direct string formatting
    query = f"SELECT id, username, email, role FROM users LIMIT {limit}"
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "role": row[3]
            })
        
        return {
            "users": users,
            "query_executed": query  # For educational purposes
        }
    
    except Exception as e:
        conn.close()
        return {"error": str(e), "query_executed": query}

@app.get("/debug/db-schema")
async def get_db_schema():
    """Debug endpoint to show database schema"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    schema = {}
    for table in tables:
        table_name = table[0]
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        schema[table_name] = [{"name": col[1], "type": col[2]} for col in columns]
    
    conn.close()
    return {"schema": schema}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
"""
A03 - Injection (Secure Implementation)
Demonstrates how to prevent SQL Injection vulnerabilities
"""

from fastapi import FastAPI, HTTPException, Depends
import sqlite3
import os
from typing import Dict, Any, Optional
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="A03 - Injection (Secure)", version="1.0.0")

# Database setup
DB_PATH = "secure_app.db"

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
    
    # Insert sample users (using parameterized queries)
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

@app.get("/")
async def root():
    return {"message": "A03 - Injection (Secure Implementation)"}

@app.post("/login")
async def login(user_data: UserLogin):
    """
    ✅ SECURE: Uses parameterized queries to prevent SQL Injection
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # ✅ SECURE: Using parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    try:
        cursor.execute(query, (user_data.username, user_data.password))
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
                }
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Database error")

@app.get("/search")
async def search_products(category: str = None, name: str = None):
    """
    ✅ SECURE: Uses parameterized queries and input validation
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Start with base query
    query = "SELECT * FROM products WHERE 1=1"
    params = []
    
    # ✅ SECURE: Using parameterized queries
    if category:
        # Input validation
        if len(category) > 50:
            raise HTTPException(status_code=400, detail="Category name too long")
        query += " AND category = ?"
        params.append(category)
    
    if name:
        # Input validation
        if len(name) > 100:
            raise HTTPException(status_code=400, detail="Product name too long")
        query += " AND name LIKE ?"
        params.append(f"%{name}%")
    
    try:
        cursor.execute(query, params)
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
        
        return {"products": products}
    
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Database error")

@app.get("/users")
async def get_users(limit: int = 10):
    """
    ✅ SECURE: Uses parameterized queries and input validation
    """
    # Input validation
    if not isinstance(limit, int) or limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="Invalid limit parameter")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # ✅ SECURE: Using parameterized query
    query = "SELECT id, username, email, role FROM users LIMIT ?"
    
    try:
        cursor.execute(query, (limit,))
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
        
        return {"users": users}
    
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Database error")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8004)
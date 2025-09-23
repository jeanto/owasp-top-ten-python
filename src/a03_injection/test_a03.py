"""
A03 - Injection Tests
Tests for SQL Injection vulnerabilities and their fixes
"""

import pytest
import requests
import time
import subprocess
import signal
import os
from multiprocessing import Process

# Server URLs
VULNERABLE_URL = "http://localhost:8003"
SECURE_URL = "http://localhost:8004"

class TestA03Injection:
    
    @classmethod
    def setup_class(cls):
        """Start both servers for testing"""
        cls.vulnerable_process = None
        cls.secure_process = None
        
        # Start vulnerable server
        cls.vulnerable_process = subprocess.Popen([
            "python", "server.py"
        ], cwd="src/a03_injection")
        
        # Start secure server
        cls.secure_process = subprocess.Popen([
            "python", "solution.py"
        ], cwd="src/a03_injection")
        
        # Wait for servers to start
        time.sleep(3)
    
    @classmethod
    def teardown_class(cls):
        """Stop both servers after testing"""
        if cls.vulnerable_process:
            cls.vulnerable_process.terminate()
            cls.vulnerable_process.wait()
        
        if cls.secure_process:
            cls.secure_process.terminate()
            cls.secure_process.wait()
        
        # Clean up database files
        for db_file in ["vulnerable_app.db", "secure_app.db"]:
            if os.path.exists(db_file):
                os.remove(db_file)

    def test_vulnerable_sql_injection_login_bypass(self):
        """Test SQL injection in login endpoint (vulnerable server)"""
        # SQL injection payload to bypass authentication
        payload = {
            "username": "admin' OR '1'='1' --",
            "password": "anything"
        }
        
        response = requests.post(f"{VULNERABLE_URL}/login", json=payload)
        
        # Should succeed due to SQL injection vulnerability
        assert response.status_code == 200
        data = response.json()
        assert data["success"] == True
        assert "admin" in data["user"]["username"]
        
        # Check that the vulnerable query was executed
        assert "OR '1'='1'" in data["query_executed"]

    def test_secure_blocks_sql_injection_login(self):
        """Test that secure server blocks SQL injection in login"""
        # Same SQL injection payload
        payload = {
            "username": "admin' OR '1'='1' --",
            "password": "anything"
        }
        
        response = requests.post(f"{SECURE_URL}/login", json=payload)
        
        # Should fail - no user with that exact username
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    def test_vulnerable_union_injection_search(self):
        """Test UNION SQL injection in search endpoint (vulnerable server)"""
        # UNION injection to extract user data
        injection_payload = "electronics' UNION SELECT id, username, password, email, role FROM users --"
        
        response = requests.get(f"{VULNERABLE_URL}/search", params={"category": injection_payload})
        
        # Should succeed and potentially expose user data
        assert response.status_code == 200
        data = response.json()
        
        # Check if injection was executed
        assert "UNION SELECT" in data["query_executed"]
        
        # Check if we got user data in products response
        products = data.get("products", [])
        # Look for usernames in the "name" field (due to UNION structure)
        usernames_found = any("admin" in str(product.get("name", "")) for product in products)
        
        # The injection should reveal sensitive data
        assert len(products) > 0

    def test_secure_blocks_union_injection_search(self):
        """Test that secure server blocks UNION injection in search"""
        # Same UNION injection payload
        injection_payload = "electronics' UNION SELECT id, username, password, email, role FROM users --"
        
        response = requests.get(f"{SECURE_URL}/search", params={"category": injection_payload})
        
        # Should return normal results (parameterized query treats payload as literal string)
        assert response.status_code == 200
        data = response.json()
        
        # Should not find any products with that exact category name
        assert len(data["products"]) == 0

    def test_vulnerable_numeric_injection_users(self):
        """Test numeric SQL injection in users endpoint (vulnerable server)"""
        # Injection in numeric parameter
        injection_payload = "1; DROP TABLE users; --"
        
        response = requests.get(f"{VULNERABLE_URL}/users", params={"limit": injection_payload})
        
        # Might return error due to malformed SQL, but injection attempt is made
        data = response.json()
        
        # Check that the injection was attempted
        if "query_executed" in data:
            assert "DROP TABLE" in data["query_executed"]

    def test_secure_validates_numeric_input(self):
        """Test that secure server validates numeric input"""
        # Invalid numeric input
        response = requests.get(f"{SECURE_URL}/users", params={"limit": "invalid"})
        
        # Should return validation error
        assert response.status_code == 422  # FastAPI validation error

    def test_legitimate_login_works_on_both_servers(self):
        """Test that legitimate login works on both servers"""
        legitimate_payload = {
            "username": "alice",
            "password": "alice123"
        }
        
        # Test vulnerable server
        response_vuln = requests.post(f"{VULNERABLE_URL}/login", json=legitimate_payload)
        assert response_vuln.status_code == 200
        assert response_vuln.json()["user"]["username"] == "alice"
        
        # Test secure server
        response_secure = requests.post(f"{SECURE_URL}/login", json=legitimate_payload)
        assert response_secure.status_code == 200
        assert response_secure.json()["user"]["username"] == "alice"

    def test_legitimate_search_works_on_both_servers(self):
        """Test that legitimate search works on both servers"""
        # Test vulnerable server
        response_vuln = requests.get(f"{VULNERABLE_URL}/search", params={"category": "electronics"})
        assert response_vuln.status_code == 200
        assert len(response_vuln.json()["products"]) > 0
        
        # Test secure server
        response_secure = requests.get(f"{SECURE_URL}/search", params={"category": "electronics"})
        assert response_secure.status_code == 200
        assert len(response_secure.json()["products"]) > 0

    def test_database_schema_endpoint(self):
        """Test database schema debug endpoint"""
        response = requests.get(f"{VULNERABLE_URL}/debug/db-schema")
        assert response.status_code == 200
        
        schema = response.json()["schema"]
        assert "users" in schema
        assert "products" in schema
        
        # Check that users table has expected columns
        user_columns = [col["name"] for col in schema["users"]]
        assert "username" in user_columns
        assert "password" in user_columns
        assert "email" in user_columns

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
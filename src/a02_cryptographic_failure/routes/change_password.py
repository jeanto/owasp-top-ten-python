import sys
import os
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'shared')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'utils')))

from auth import get_current_user, db
from crypto import hash_md5

router = APIRouter()

class ChangePasswordRequest(BaseModel):
    new_password: str

@router.post("/change-password")
async def change_password(request: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    # VULNERÁVEL: Armazena senha com hash MD5
    password_hash = hash_md5(request.new_password)
    query = "UPDATE users SET password = %s WHERE username = %s"
    conn = db.get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, (password_hash, current_user["username"]))
            conn.commit()
            if cursor.rowcount > 0:
                return {"message": "Senha alterada com sucesso (MD5)"}
            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuário não encontrado")
    finally:
        conn.close()

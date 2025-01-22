from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import json
import subprocess
import pty


SUPERADMIN_CPP_PATH = "./PKI_CPP/build/superadmin"
REGISTRATOR_CPP_PATH = "./PKI_CPP/build/registrar"
ADMIN_CPP_PATH = "./PKI_CPP/build/admin"

load_dotenv()

app = FastAPI()

class ConnectRequest(BaseModel):
    username: str
    password: str

class CreateRequest(BaseModel):
    registrar: str
    request_data: str

# Состояние системы
system_initialized = False
users_connected = {
    "superadmin": False,
    "admin": False,
    "registrar": False
}

superadmin_login = os.getenv('SUPERADMIN_LOGIN')
superadmin_password = os.getenv('SUPERADMIN_PASSWORD')
admin_login = os.getenv('ADMIN_LOGIN')
admin_password = os.getenv('ADMIN_PASSWORD')
registrator_login = os.getenv('REGISTRATOR_LOGIN')
registrator_password = os.getenv('REGISTRATOR_PASSWORD')

@app.post("/init")
def init_system(request: ConnectRequest):
    global system_initialized
    
    # Проверка, что это супер-админ
    if request.username != superadmin_login or request.password != superadmin_password:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    system_initialized = True

    # Возвращаем данные для запуска C++ программы
    return {
        "status": "success",
        "message": "Authorization successful",
        "cpp_program": SUPERADMIN_CPP_PATH,  # Путь к C++ программе
    }


@app.post("/registrator")
def authorize_registrator(request: ConnectRequest):
    global system_initialized
    
    if request.username != registrator_login or request.password != registrator_password:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    if not system_initialized:
        return {
            "status": "failed",
            "message": "Система еще не была инициализирована суперадминистратором.\nВы не можете ее использовать.",
        }
    
    return {
        "status": "success",
        "message": "Authorization successful",
        "cpp_program": REGISTRATOR_CPP_PATH,
    }


@app.post("/admin")
def authorize_registrator(request: ConnectRequest):
    global system_initialized
    
    if request.username != admin_login or request.password != admin_password:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    if not system_initialized:
        return {
            "status": "failed",
            "message": "Система еще не была инициализирована суперадминистратором.\nВы не можете ее использовать.",
        }
    
    return {
        "status": "success",
        "message": "Authorization successful",
        "cpp_program": ADMIN_CPP_PATH,
    }

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5050)
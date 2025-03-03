from fastapi import APIRouter, Depends, FastAPI, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from pydantic import BaseModel
import sqlite3
import os

app = FastAPI()

async def auth_middleware(request: Request, call_next):
    token = request.headers.get('Authorization')

    if not token:
        return JSONResponse(status_code=401, content={'message': 'Token não fornecido'})
    
    try:
        payload = jwt.decode(token.split('Bearer ')[1], SECRET_KEY, algorithms=[ALGORITHM])
        request.state.user = payload.get('sub')

    except JWTError:
        return JSONResponse(status_code=401, content={'message': 'Token inválido'})
    
    response = await call_next(request)
    return response

app.middleware("http")(auth_middleware)


# Configuração JWT
SECRET_KEY = os.getenv('SECRET_KEY','c2b5c5f5a8c3e8e0b6e8c')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configuração do bcrypt
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# Configuração do OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

# Conectar ao banco de dados SQLite
conn = sqlite3.connect('finance.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')
conn.commit()

# Criar um router para autenticação
router = APIRouter()

# Modelo de usuário
class User(BaseModel):
    username: str
    password: str

# Gerar hash da senha
def hash_password(password: str):
    return pwd_context.hash(password)

# Verificar senha
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Criar token JWT
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({'exp': expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Rota de registro de usuário
@router.post('/register/')
def register(user: User):
    hashed_password = hash_password(user.password)
    try:
        with sqlite3.connect('finance.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (user.username, hashed_password))
            conn.commit()
        return {'message': 'Usuário registrado com sucesso'}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail='Nome de usuário já existe')


# Rota para login e geração do token
@router.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with sqlite3.connect('finance.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (form_data.username,))
        user = cursor.fetchone()

        if not user or not verify_password(form_data.password, user[1]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

        access_token = create_access_token(data={"sub": form_data.username})
        return {"access_token": access_token, "token_type": "bearer", "username": form_data.username}


# Função para validar o usuário autenticado
def get_current_user(token: str = Depends(oauth2_scheme)):
    cursor.execute('SELECT * FROM token_blacklist WHERE token = ?', (token,))
    if cursor.fetchone():
        raise HTTPException(status_code=401, detail='Token inválido')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")


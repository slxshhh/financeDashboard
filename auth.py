from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from pydantic import BaseModel
import sqlite3

# Configurando o JWT 
SECRET_KEY = 'c2b5c5f5a8c3e8e0b6e8c'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuranção do bcrypt
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# Configuração do OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

# Conexão com o banco de dados SQLite
conn = sqlite3.connect('finance.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
               CREATE TABLE IF NOT EXISTS users(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   password TEXT NOT NULL
               )
               ''')
conn.commit()

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

# Criação token JWT
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({'exp': expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Rota de registro de novo usuário
app = FastAPI()

@app.post('/register/')
def register(user: User):
    hashed_password = hash_password(user.password)
    try:
       payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
       username: str = payload.get('sub')
       if username is None:
           raise HTTPException(status_code= status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
       return username
    except JWTError:
        raise HTTPException(status_code= status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
    
# Rota para login e geração do token
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    cursor.execute("SELECT id, hashed_password FROM users WHERE username = ?", (form_data.username,))
    user = cursor.fetchone()

    if not user or not verify_password(form_data.password, user[1]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Função para validar o usuário autenticado
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
from fastapi import Depends, FastAPI, HTTPException
from auth import get_current_user
from pydantic import BaseModel
from typing import List
import sqlite3
from fastapi import FastAPI
from auth import router as auth_router  # Importando o router do auth.py
from fastapi import FastAPI
from auth import router as auth_router  # Importando o router do auth.py

app = FastAPI()

# Incluindo as rotas de autenticação
app.include_router(auth_router)

# Conexão com o banco de dados SQLite
conn = sqlite3.connect('finance.db', check_same_thread=False)
cursor = conn.cursor()

# Criação da tabela de transações
cursor.execute('''
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT NOT NULL,
    amount REAL NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
    date TEXT NOT NULL
    )
''')

conn.commit()

#Modelo de dados
class Transaction(BaseModel):
    description: str
    amount: float
    type: str 
    date: str

# Nova transação
@app.post('/transactions/')
def create_transaction(transaction: Transaction, user: str = Depends(get_current_user)):
    cursor.execute('''
    INSERT INTO transactions (description, amount, type, date)
    VALUES (?, ?, ?, ?)
    ''', (transaction.description, transaction.amount, transaction.type, transaction.date))
    conn.commit()
    return {'message': 'Transação adicionada com sucesso'}

# Listar todas as transações
@app.get('/transactions/', response_model = List[Transaction])
def get_transactions():
    cursor.execute('SELECT description, amount, tyupe, date FROM transactions')
    transactions = cursor.fetchall()
    return [{"description": t[0], "amount": t[1], "type": t[2], "date": t[3]} for t in transactions]

# Deletar uma transação por ID
@app.delete('/transactions/{transaction_id}/')
def delete_transaction(transaction_id: int):
    cursor.execute('DELETE FROM transactions WHERE id = ?', (transaction_id,))
    conn.commit()
    return {'message': 'Transação deletada com sucesso'}

# Iniciando servidor
if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port = 8000)
from auth import ACCESS_TOKEN_EXPIRE_MINUTES, get_current_user, hash_password, oauth2_scheme
from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import sqlite3
from fastapi import FastAPI, Query
from auth import router as auth_router


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

# Criação da tabela de tokens revogados
cursor.execute('''
CREATE TABLE IF NOT EXISTS token_blacklist(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    expiry TIMESTAMP NOT NULL
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
def get_transactions(
    type: str = Query(None, description='Filtrar por tipo de transação (income ou expense)'),
    start_date: str = Query(None, description='Filtrar por data mínima (YYY7-MM-DD)'),
    end_date: str = Query(None, description='Filtrar por data máxima (YYY7-MM-DD)'),
    order_by: str = Query('date', description='Ordenar por "amount" ou "date"'),
    order: str = Query(None, dedscription='Ordenar de forma crescente (asc) ou decrescente (desc)')
    ):
    query = 'SELECT description, amount, type, date FROM transactions WHERE 1 = 1'
    params = []
    # Filtragem dinâmica
    if type:
        query += ' AND type = ?'
        params.append(type)
    
    if start_date:
        query += ' AND date >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND date <= ?'
        params.append(end_date)
    
    # Ordenação
    if order_by in ['amount', 'date']:
        order_direction = 'ASC' if order == 'asc' else 'DESC'
        query += f'ORDER BY {order_by} {order_direction}'
    
    cursor.execute(query, tuple(params))
    transactions = cursor.fetchall()
    return [{"description": t[0], "amount": t[1], "type": t[2], "date": t[3]} for t in transactions]

# Editar uma transação por ID
@app.put('/transactions/{transaction_id}/')
def update_transaction(transaction_id: int, transaction: Transaction, user: str = Depends(get_current_user)):
    cursor.execute('SELECT * FROM transactions WHERE id = ?', (transaction_id,))
    existing_transaction = cursor.fetchone()
    if not existing_transaction:
        raise HTTPException(status_code=404, detail='Transação não encontrada')
    
    cursor.execute('''
        UPDATE transactions
                   SET description = ?,
                       amount = ?,
                       type = ?,
                       date = ?
                    WHERE id = ?               
                   

    '''), (transaction.description, transaction.amount, transaction.type, transaction.date, transaction_id)
    conn.commit()
    return {'message': 'Transação atualizada com sucesso'}

# Deletar uma transação por ID
@app.delete('/transactions/{transaction_id}/')
def delete_transaction(transaction_id: int):
    cursor.execute('DELETE FROM transactions WHERE id = ?', (transaction_id,))
    conn.commit()
    return {'message': 'Transação deletada com sucesso'}

class UpdateUser(BaseModel):
    username: str
    password: str

# Rota de atualização de Usuário
@app.put('/users/update/')
def update_user(user: UpdateUser, token: str = Depends(oauth2_scheme)):
    cursor.execute('UPDATE users SET password = ? WHERE username = ?',
                   (hash_password(user.password), user.username))
    conn.commit()
    return {'message': 'Senha atualizado com sucesso'}

# Rota de logout 
@app.post("/logout/")
def logout(token: str = Depends(oauth2_scheme)):
    expire_time = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    cursor.execute("INSERT INTO token_blacklist (token, expiry) VALUES (?, ?)", (token, expire_time))
    conn.commit()
    return {"message": "Logout realizado com sucesso"}

# Iniciando servidor
if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port = 8000)

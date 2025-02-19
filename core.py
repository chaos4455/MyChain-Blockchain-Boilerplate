import hashlib
import json
import time
from typing import List, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError, field_validator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding

import uvicorn
import logging
import sqlite3
import os

# Configuração de Logs
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s') #Mudado para DEBUG
logger = logging.getLogger(__name__)

DATABASE_FILE = "blockchain.db"  # Arquivo do banco de dados SQLite

app = FastAPI()

# CORS para permitir requisições de diferentes origens (localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção, restrinja as origens
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configurações
MASTER_NODES = 3
PORT = 17222  # Porta padrão
DIFFICULTY = 4
BLOCK_REWARD = 10  # Recompensa por minerar um bloco
MIN_TRANSACTION_AMOUNT = 0.00000001 # Previne ataques de spam com micro transações
GENESIS_ADDRESS = "Genesis" #Carteira Genesis
BLOCKCHAIN_REWARD_ADDRESS = "BlockchainReward" # Endereço para recompensas de mineração

# ------------------- Segurança RSA -------------------

def generate_keys():
    """Gera um par de chaves RSA (privada e pública)."""
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    except Exception as e:
        logger.error(f"Erro ao gerar chaves RSA: {e}")
        raise

def load_key(key_string: str, private=False):
    """Carrega uma chave RSA (privada ou pública) a partir de uma string."""
    try:
        key_bytes = key_string.encode('utf-8')
        if private:
            return serialization.load_pem_private_key(
                key_bytes,
                password=None,
                backend=default_backend()
            )
        else:
            return serialization.load_pem_public_key(
                key_bytes,
                backend=default_backend()
            )
    except Exception as e:
        logger.error(f"Erro ao carregar chave RSA: {e}")
        raise

def sign_data(private_key_pem: str, data: str) -> bytes:
    """Assina os dados fornecidos com a chave privada RSA."""
    try:
        private_key = load_key(private_key_pem, True)
        message = data.encode('utf-8')
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    except Exception as e:
        logger.error(f"Erro ao assinar dados: {e}")
        raise

def verify_signature(public_key_pem: str, signature: bytes, data: str) -> bool:
    """Verifica se a assinatura corresponde aos dados e à chave pública RSA."""
    try:
        public_key = load_key(public_key_pem)
        message = data.encode('utf-8')
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        logger.warning("Assinatura inválida.")
        return False
    except Exception as e:
        logger.error(f"Erro na verificação da assinatura: {e}")
        return False

# ------------------- Modelo de Dados -------------------

class Transaction(BaseModel):
    sender: str
    recipient: str
    amount: float
    signature: str

    def __hash__(self):  # Adiciona um hash para comparar transações
        return hash((self.sender, self.recipient, self.amount, self.signature))

    @field_validator('amount')
    def amount_must_be_positive(cls, value):
        if value <= MIN_TRANSACTION_AMOUNT:
            raise ValueError(f'Amount must be greater than {MIN_TRANSACTION_AMOUNT}')
        return value

class Block(BaseModel):
    index: int
    timestamp: float
    transactions: List[Transaction]
    previous_hash: str
    nonce: int
    miner: str  # Adiciona o minerador do bloco
    master_node_signatures: List[str]  # Lista de assinaturas dos nós mestres

    def compute_hash(self):
        """Calcula o hash SHA-256 do bloco."""
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "miner": self.miner,
            "master_node_signatures": self.master_node_signatures
        }
        logger.debug(f"Block.compute_hash - block_data: {block_data}") # Log block_data before hashing #ADICIONADO LOG
        # Serializa o dicionário para JSON e calcula o hash
        block_string = json.dumps(block_data, sort_keys=True, ensure_ascii=False).encode('utf-8') # ensure_ascii=False
        return hashlib.sha256(block_string).hexdigest()

    def is_valid(self, previous_block: Optional["Block"] = None) -> bool:
        """Valida o bloco, verificando índice, hash anterior, transações e PoW."""
        if previous_block:
            if self.index != previous_block.index + 1:
                logger.error(f"Índice do bloco inválido. Esperado: {previous_block.index + 1}, Recebido: {self.index}")
                return False
            if self.previous_hash != previous_block.compute_hash():
                logger.error(f"Hash do bloco anterior inválido.")
                return False

            #Verifica se as transações são validas
            for transaction in self.transactions:
                if not verify_transaction_signature(transaction):
                    logger.error(f"Assinatura da transação inválida: {transaction}")
                    return False

        if not is_valid_proof(self):
            logger.error("Proof-of-Work inválido.")
            return False

        return True

class BlockchainState(BaseModel):
    chain: List[Block]
    pending_transactions: List[Transaction]
    master_node_public_keys: dict

class NodeRegistration(BaseModel):
    public_key: str

# ------------------- Estado da Blockchain (Em Memória e Banco) -------------------

# Inicializa a blockchain com Pandas DataFrame
blockchain_df = pd.DataFrame(columns=[
    "block_index", "timestamp", "transactions", "previous_hash", "nonce", "miner", "hash", "master_node_signatures"
])

# Lista de transações pendentes
pending_transactions: List[Transaction] = []

# Lista de chaves publicas dos Master Nodes
master_node_public_keys: List[str] = []

# ------------------- Funções Blockchain -------------------

def proof_of_work(block: Block) -> int:
    """Executa o Proof-of-Work para encontrar um nonce válido para o bloco."""
    block.nonce = 0
    computed_hash = block.compute_hash()
    while not computed_hash.startswith('0' * DIFFICULTY):
        block.nonce += 1
        computed_hash = block.compute_hash()
    return block.nonce

def create_genesis_block():
    """Cria e adiciona o bloco Gênesis à blockchain."""
    try:
        global blockchain_df  # Declara que estamos usando a variável global

        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            transactions=[],
            previous_hash="0",
            nonce=0,
            miner=GENESIS_ADDRESS,
            master_node_signatures=[]
        )
        genesis_block_hash = genesis_block.compute_hash()
        add_block_to_blockchain(genesis_block, genesis_block_hash)
        logger.info("Bloco Gênesis criado.")
    except Exception as e:
        logger.error(f"Erro ao criar bloco Gênesis: {e}")
        raise

def add_block_to_blockchain(block: Block, block_hash: str):
    """Adiciona um bloco validado à blockchain e o persiste no banco de dados."""
    try:
        global blockchain_df  # Acessa a variável global

        # Converte o bloco para um dicionário para salvar no DataFrame
        block_data = {
            "block_index": block.index,
            "timestamp": block.timestamp,
            "transactions": [tx.dict() for tx in block.transactions],  # Converte as transações para dicionários
            "previous_hash": block.previous_hash,
            "nonce": block.nonce,
            "miner": block.miner,
            "hash": block_hash,
            "master_node_signatures": block.master_node_signatures
        }

        # Cria um novo DataFrame com os dados do bloco
        new_block_df = pd.DataFrame([block_data])

        # Concatena o novo DataFrame com o DataFrame da blockchain
        blockchain_df = pd.concat([blockchain_df, new_block_df], ignore_index=True)

        # Persiste no banco de dados
        persist_block_to_db(block, block_hash)
        logger.info(f"Bloco {block.index} adicionado à blockchain.")

    except Exception as e:
        logger.error(f"Erro ao adicionar bloco à blockchain: {e}")
        raise

def get_last_block() -> tuple[Optional[Block], Optional[str]]:
    """Retorna o último bloco da blockchain e seu hash, ou None se a blockchain estiver vazia."""
    try:
        global blockchain_df

        if len(blockchain_df) == 0:
            return None, None # Blockchain vazia

        # Obtem a ultima linha do DataFrame
        last_block_series = blockchain_df.iloc[-1]

        # Transforma a Series do pandas para dict para criar o modelo Block
        last_block_dict = last_block_series.to_dict()
        # Certifica-se de que 'index' está presente e é um int, renomeando 'block_index' para 'index'
        if 'block_index' in last_block_dict:
            last_block_dict['index'] = int(last_block_dict.pop('block_index')) # Renomeia e converte
        else:
            logger.error("Chave 'block_index' não encontrada no último bloco recuperado do DataFrame.")
            return None, None

        last_block = Block(**last_block_dict)
        return last_block, last_block_series["hash"]
    except Exception as e:
        logger.error(f"Erro ao obter o último bloco: {e}")
        return None, None

def get_blockchain() -> List[Block]:
    """Retorna a cadeia de blocos completa como uma lista de objetos Block."""
    try:
        global blockchain_df

        if len(blockchain_df) == 0:
            return [] # Blockchain vazia

        chain = []
        for _, row in blockchain_df.iterrows():
            block_dict = row.to_dict()
             # Certifica-se de que 'index' está presente e é um int, renomeando 'block_index' para 'index'
            if 'block_index' in block_dict:
                block_dict['index'] = int(block_dict.pop('block_index')) # Renomeia e converte
            else:
                logger.error("Chave 'block_index' não encontrada ao carregar bloco do DataFrame.")
                continue # Pula este bloco se o índice estiver faltando

            try:
                block = Block(**block_dict)
                chain.append(block)
            except ValidationError as e:
                logger.error(f"Erro de validação ao criar bloco do DataFrame: {e}")
                continue # Pula blocos inválidos

        return chain
    except Exception as e:
        logger.error(f"Erro ao obter a blockchain: {e}")
        return []

def add_pending_transaction(transaction: Transaction):
    """Adiciona uma transação à lista de transações pendentes após validação."""
    try:
        global pending_transactions
         #Validar assinatura da transação
        if not verify_transaction_signature(transaction):
            logger.error(f"Transação com assinatura inválida: {transaction}")
            raise HTTPException(status_code=400, detail="Assinatura da transação inválida.")

        #Validar saldo do remetente (exceto para transações Genesis)
        if transaction.sender != GENESIS_ADDRESS:
            sender_balance = calculate_balance(transaction.sender)
            if sender_balance < transaction.amount:
                 logger.error(f"Saldo insuficiente para a transação: {transaction}")
                 raise HTTPException(status_code=400, detail="Saldo insuficiente.")
        pending_transactions.append(transaction)
        logger.info(f"Transação adicionada à lista pendente: {transaction}")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Erro ao adicionar transação pendente: {e}")
        raise

def get_pending_transactions() -> List[Transaction]:
    """Retorna a lista atual de transações pendentes."""
    try:
        global pending_transactions
        return pending_transactions
    except Exception as e:
        logger.error(f"Erro ao obter transações pendentes: {e}")
        return []

def clear_pending_transactions(transactions: List[Transaction]):
    """Remove uma lista de transações da lista de transações pendentes."""
    try:
        global pending_transactions
        # Remova as transações fornecidas da lista pendente
        pending_transactions = [tx for tx in pending_transactions if tx not in transactions]
        logger.info("Lista de transações pendentes limpa.")
    except Exception as e:
        logger.error(f"Erro ao limpar transações pendentes: {e}")
        raise

def is_valid_chain(chain: List[Block]) -> bool:
    """Valida a integridade de toda a cadeia de blocos."""
    try:
        if not chain: # Chain vazia é valida
            return True
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            if not current_block.is_valid(previous_block):
                logger.error(f"Bloco {current_block.index} é inválido.")
                return False
            if current_block.previous_hash != previous_block.compute_hash():
                logger.error(f"Hash do bloco anterior inválido no bloco {current_block.index}.")
                return False
            # Removed DB hash check - relying on object hash and validation for now
            # if current_block.compute_hash() != get_block_hash_from_db(current_block.index): #Verifica hash com o hash do DB
            #      logger.error(f"Hash do bloco {current_block.index} não corresponde ao hash no banco de dados.")
            #      return False
        return True
    except Exception as e:
        logger.error(f"Erro ao validar cadeia de blocos: {e}")
        return False

def get_block_hash_from_db(block_index: int) -> Optional[str]:
    """Recupera o hash de um bloco específico do banco de dados pelo seu índice."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("SELECT hash FROM blockchain WHERE block_index = ?", (block_index,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
    except sqlite3.Error as e:
        logger.error(f"Erro ao obter hash do bloco do banco de dados: {e}")
        return None
    finally:
        if conn:
            conn.close()

def register_master_node(public_key: str):
    """Registra a chave pública de um nó mestre, adicionando-a à lista e ao banco de dados."""
    try:
        global master_node_public_keys
        if public_key not in master_node_public_keys:
            master_node_public_keys.append(public_key)
            persist_master_node_to_db(public_key)
            logger.info(f"Nó mestre registrado com chave pública: {public_key}")
        else:
             logger.info(f"Nó mestre ja registrado: {public_key}")
    except Exception as e:
        logger.error(f"Erro ao registrar nó mestre: {e}")
        raise

def get_master_node_public_keys() -> List[str]:
    """Retorna a lista de chaves públicas de todos os nós mestres registrados."""
    try:
        global master_node_public_keys
        return master_node_public_keys
    except Exception as e:
        logger.error(f"Erro ao obter chaves públicas de nós mestres: {e}")
        return []

def is_valid_proof(block: Block) -> bool:
    """Verifica se o hash do bloco satisfaz a condição de dificuldade do Proof-of-Work."""
    try:
        computed_hash = block.compute_hash()
        return computed_hash.startswith('0' * DIFFICULTY)
    except Exception as e:
        logger.error(f"Erro ao validar Proof-of-Work: {e}")
        return False

def calculate_balance(address: str) -> float:
    """Calcula o saldo de uma carteira, percorrendo a blockchain."""
    try:
        balance = 0.0
        chain = get_blockchain()
        for block in chain:
            for transaction in block.transactions:
                if transaction.recipient == address:
                    balance += transaction.amount
                if transaction.sender == address:
                    balance -= transaction.amount
        return balance
    except Exception as e:
        logger.error(f"Erro ao calcular saldo: {e}")
        return 0.0

def verify_transaction_signature(transaction: Transaction) -> bool:
    """Verifica a assinatura de uma transação usando a chave pública do remetente."""
    try:
        # Transações Genesis não precisam de assinatura
        if transaction.sender == GENESIS_ADDRESS:
            return True

        # Prepara os dados da transação para verificação (sem a assinatura)
        data = f"{transaction.sender}{transaction.recipient}{transaction.amount}"
        signature_bytes = bytes.fromhex(transaction.signature)

        # Recupera a chave pública do remetente
        public_key_pem = get_public_key_for_address(transaction.sender)

        if not public_key_pem:
            logger.warning(f"Chave pública não encontrada para o endereço: {transaction.sender}")
            return False

        return verify_signature(public_key_pem, signature_bytes, data)
    except Exception as e:
        logger.error(f"Erro ao verificar assinatura da transação: {e}")
        return False

# ------------------- Funções de persistencia no Banco de Dados -------------------

def connect_to_db():
    """Estabelece e retorna uma conexão com o banco de dados SQLite."""
    conn = None # Inicializa conn fora do bloco try
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        logger.debug("Conectado ao banco de dados SQLite.") # Log de debug
        return conn
    except sqlite3.Error as e:
        logger.error(f"Erro ao conectar ao banco de dados: {e}")
        if conn: # Tenta fechar a conexão mesmo se falhou na abertura (limpeza)
            conn.close()
        raise

def create_tables():
    """Cria as tabelas `blockchain`, `master_nodes` e `wallet_keys` no banco de dados, se não existirem."""
    conn = None # Garante que conn seja definido mesmo se a conexão falhar
    try:
        conn = connect_to_db()
        cursor = conn.cursor()

        # Tabela para a blockchain
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blockchain (
                block_index INTEGER PRIMARY KEY,
                timestamp REAL NOT NULL,
                transactions TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                nonce INTEGER NOT NULL,
                miner TEXT NOT NULL,
                hash TEXT NOT NULL,
                master_node_signatures TEXT
            )
        """)

        # Tabela para nós mestres
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS master_nodes (
                public_key TEXT PRIMARY KEY
            )
        """)

        # Tabela para mapear endereços para chaves publicas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wallet_keys (
                address TEXT PRIMARY KEY,
                public_key TEXT NOT NULL
            )
        """)

        conn.commit()
        logger.info("Tabelas do banco de dados criadas/verificadas.")
    except sqlite3.Error as e:
        logger.error(f"Erro ao criar tabelas no banco de dados: {e}")
        raise
    finally:
        if conn:
            conn.close()

def persist_block_to_db(block: Block, block_hash: str):
    """Persiste os dados de um bloco no banco de dados."""
    conn = None
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO blockchain (block_index, timestamp, transactions, previous_hash, nonce, miner, hash, master_node_signatures)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            block.index,
            block.timestamp,
            json.dumps([tx.dict() for tx in block.transactions], ensure_ascii=False), # ensure_ascii=False
            block.previous_hash,
            block.nonce,
            block.miner,
            block_hash,
            json.dumps(block.master_node_signatures, ensure_ascii=False) # ensure_ascii=False
        ))
        conn.commit()
        logger.info(f"Bloco {block.index} persistido no banco de dados.")
    except sqlite3.Error as e:
        logger.error(f"Erro ao persistir bloco no banco de dados: {e} - Block Index: {block.index}, Hash: {block_hash}") # Adiciona info do bloco no log
        raise
    finally:
        if conn:
            conn.close()

def persist_master_node_to_db(public_key: str):
    """Persiste a chave pública de um nó mestre no banco de dados."""
    conn = None
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO master_nodes (public_key)
            VALUES (?)
        """, (public_key,))
        conn.commit()
        logger.info(f"Nó mestre com chave pública {public_key} persistido no banco de dados.")
    except sqlite3.Error as e:
        logger.error(f"Erro ao persistir nó mestre no banco de dados: {e}")
        raise
    finally:
        if conn:
            conn.close()

def load_master_nodes_from_db():
    """Carrega as chaves públicas dos nós mestres do banco de dados para a lista em memória."""
    conn = None
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM master_nodes")
        rows = cursor.fetchall()
        global master_node_public_keys
        master_node_public_keys = [row[0] for row in rows]
        logger.info("Chaves públicas dos nós mestres carregadas do banco de dados.")
    except sqlite3.Error as e:
        logger.error(f"Erro ao carregar chaves públicas dos nós mestres do banco de dados: {e}")
        raise
    finally:
        if conn:
            conn.close()

def get_public_key_for_address(address: str) -> Optional[str]:
    """Retorna a chave pública associada a um endereço de carteira do banco de dados."""
    conn = None
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM wallet_keys WHERE address = ?", (address,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
    except sqlite3.Error as e:
        logger.error(f"Erro ao obter chave pública do banco de dados: {e}")
        return None
    finally:
        if conn:
            conn.close()

def persist_wallet_key_pair_to_db(address: str, public_key: str):
    """Persiste o par endereço-chave pública de uma carteira no banco de dados."""
    conn = None
    try:
        conn = connect_to_db()
        cursor = conn.cursor()

        # Verifica se a carteira já existe
        cursor.execute("SELECT address FROM wallet_keys WHERE address = ?", (address,))
        if cursor.fetchone() is not None:
             logger.warning(f"Carteira com endereço {address} já existe.")
             raise HTTPException(status_code=400, detail=f"Carteira com endereço {address} já existe.")


        cursor.execute("""
            INSERT INTO wallet_keys (address, public_key)
            VALUES (?, ?)
        """, (address, public_key))
        conn.commit()
        logger.info(f"Chave publica para carteira {address} persistida no banco de dados.")
    except HTTPException as e:
        raise e #Re-lança a exception
    except sqlite3.Error as e:
        logger.error(f"Erro ao persistir chave publica no banco de dados: {e}")
        raise
    finally:
        if conn:
            conn.close()

def load_blockchain_from_db():
    """Carrega a blockchain completa do banco de dados para o DataFrame `blockchain_df`."""
    global blockchain_df  # Garante que estamos acessando a variável global
    blockchain_data = []  # Inicializa a lista *antes* do bloco try
    conn = None
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blockchain ORDER BY block_index ASC")
        rows = cursor.fetchall()

        for row in rows:
            block_index, timestamp, transactions_json, previous_hash, nonce, miner, hash, master_node_signatures_json = row
            transactions = [Transaction(**tx) for tx in json.loads(transactions_json)]
            master_node_signatures = json.loads(master_node_signatures_json) if master_node_signatures_json else []

            blockchain_data.append({
                "block_index": block_index,
                "timestamp": timestamp,
                "transactions": transactions,
                "previous_hash": previous_hash,
                "nonce": nonce,
                "miner": miner,
                "hash": hash,
                "master_node_signatures": master_node_signatures
            })

        blockchain_df = pd.DataFrame(blockchain_data)
        logger.info("Blockchain carregada do banco de dados para o DataFrame.")
    except sqlite3.Error as e:
        logger.error(f"Erro ao carregar blockchain do banco de dados: {e}")
        blockchain_df = pd.DataFrame(columns=[ # Garante DF vazio em caso de erro
            "block_index", "timestamp", "transactions", "previous_hash", "nonce", "miner", "hash", "master_node_signatures"
        ])
    finally:
        if conn:
            conn.close()

# ------------------- Rotas FastAPI -------------------

class NodeRegistration(BaseModel):
    public_key: str

@app.post("/register_node")
async def register_node(registration: NodeRegistration):
    """Rota para registrar um novo nó mestre."""
    logger.info("Rota /register_node acessada.")
    try:
        register_master_node(registration.public_key)
        return {"message": "Nó mestre registrado com sucesso."}
    except Exception as e:
        logger.error(f"Erro ao registrar nó mestre: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/blockchain", response_model=List[Block])
async def get_chain():
    """Rota para retornar a blockchain completa."""
    logger.info("Rota /blockchain acessada.")
    return get_blockchain()

@app.post("/transaction")
async def add_transaction(transaction: Transaction):
    """Rota para adicionar uma nova transação à lista de transações pendentes."""
    logger.info(f"Rota /transaction acessada. Transação: {transaction}")
    try:
        add_pending_transaction(transaction)
        return {"message": "Transação adicionada à lista pendente."}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Erro ao adicionar transação: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class BlockConfirmation(BaseModel):
    block: Block
    block_hash: str
    signature: str
    public_key: str

pending_block_confirmations = {}

@app.post("/confirm_block")
async def confirm_block(confirmation: BlockConfirmation):
    """Rota para confirmar um bloco minerado por um nó mestre."""
    logger.info("Rota /confirm_block acessada.")
    try:
        block = confirmation.block
        received_block_hash = confirmation.block_hash # Use received_block_hash here
        signature = confirmation.signature
        public_key = confirmation.public_key

        logger.debug(f"Bloco recebido para confirmação: {block.index}")
        logger.debug(f"Hash recebido: {received_block_hash}") # Debug received_block_hash
        logger.debug(f"Assinatura recebida: {signature}")
        logger.debug(f"Chave pública recebida: {public_key}")

        # 0. Valida se o nó mestre esta registrado
        master_node_keys = get_master_node_public_keys()
        if public_key not in master_node_keys:
            raise HTTPException(status_code=403, detail="Chave pública não autorizada.")

        # 1. Verifique a assinatura do nó mestre
        signature_bytes = bytes.fromhex(signature) # Transforma de volta para bytes
        if not verify_signature(public_key, signature_bytes, received_block_hash): # Verifique a assinatura usando o received_block_hash
            raise HTTPException(status_code=400, detail="Assinatura do nó mestre inválida.")

        # 2. Verifique o hash do bloco (usando o hash recebido!)
        if received_block_hash != block.compute_hash(): # Compare against received_block_hash
            raise HTTPException(status_code=400, detail="Hash do bloco inválido.")

        # 3. Verifique o PoW
        if not is_valid_proof(block):
            raise HTTPException(status_code=400, detail="Proof-of-Work inválido.")

        # 4. Valida o bloco em si (index, previous_hash, transações)
        last_block, last_block_hash = get_last_block()

        if last_block is None: # Trata o caso de blockchain vazia (antes do genesis?)
            if block.index != 0: # Se não for o bloco genesis, invalido
                raise HTTPException(status_code=400, detail="Bloco inválido: Blockchain vazia, esperado bloco Genesis.")
        elif block.index != last_block.index + 1: # Verifica a ordem correta do bloco
            raise HTTPException(status_code=400, detail=f"Bloco fora de ordem. Esperado índice: {last_block.index + 1}, recebido: {block.index}")
        elif not block.is_valid(last_block): # Valida normalmente se ja tem bloco genesis
             raise HTTPException(status_code=400, detail="Bloco inválido: Validação do bloco falhou.")


        # 5. Lógica de Consenso (2/3 dos nós mestres)
        block_key = block.index  # Identificador único para o bloco

        # Verifica se já existe um bloco confirmado com este índice (evitar duplicados)
        current_chain = get_blockchain()
        if any(b.index == block.index for b in current_chain):
            raise HTTPException(status_code=409, detail=f"Bloco com índice {block.index} já foi confirmado e adicionado.")


        # Armazena as informações do bloco e a assinatura do nó mestre
        if block_key not in pending_block_confirmations:
            pending_block_confirmations[block_key] = {
                "block": block,
                "block_hash": received_block_hash, # Store received_block_hash
                "signatures": [],
                "public_keys": []
            }

        # Adiciona a assinatura e a chave pública do nó mestre que confirmou
        if public_key not in pending_block_confirmations[block_key]["public_keys"]: # Evita confirmações duplicadas do mesmo nó
            pending_block_confirmations[block_key]["signatures"].append(signature)
            pending_block_confirmations[block_key]["public_keys"].append(public_key)
            logger.info(f"Confirmação do bloco {block.index} recebida do nó mestre {public_key[:20]}...") # Log mais detalhado

        else:
            logger.warning(f"Confirmação duplicada do nó mestre {public_key[:20]}... para o bloco {block.index} ignorada.")
            return {"message": f"Confirmação duplicada recebida e ignorada."}


        # Verifica se o consenso foi atingido (mais de 2/3 dos nós mestres únicos)
        unique_public_keys = set(pending_block_confirmations[block_key]["public_keys"])
        if len(unique_public_keys) >= (2 * MASTER_NODES) / 3:  # Mais de 2/3
            logger.info(f"Consenso atingido para o bloco {block.index} com {len(unique_public_keys)} confirmações.") # Log de consenso atingido
            # Validar e adicionar o bloco
            block_to_add = pending_block_confirmations[block_key]["block"]
            signatures_for_block = pending_block_confirmations[block_key]["signatures"] # Pega as assinaturas coletadas
            stored_block_hash = pending_block_confirmations[block_key]["block_hash"] # Get stored_block_hash

            if validate_and_add_block(block_to_add, stored_block_hash, signatures_for_block, list(unique_public_keys)): # Pass stored_block_hash
                # Dar a recompensa ao minerador
                reward_transaction = Transaction(sender=BLOCKCHAIN_REWARD_ADDRESS, recipient=block.miner, amount=BLOCK_REWARD, signature="") # Recompensa vem do endereço de recompensa
                add_pending_transaction(reward_transaction)

                # Limpar as transações pendentes que foram incluídas no bloco
                clear_pending_transactions(block.transactions)
                del pending_block_confirmations[block_key] # Limpa confirmações pendentes para este bloco
                return {"message": f"Bloco {block.index} adicionado à blockchain com consenso."}
            else:
                # Se validate_and_add_block falhar, algo inesperado aconteceu (já validamos antes!)
                logger.error(f"Falha ao validar e adicionar bloco {block.index} APÓS consenso! Verifique logs de validate_and_add_block.")
                raise HTTPException(status_code=500, detail="Erro ao adicionar bloco após consenso (validação falhou).")
        else:
            # Consenso não atingido ainda
            faltam = (2*MASTER_NODES/3) - len(unique_public_keys)
            logger.info(f"Confirmação recebida para o bloco {block.index}. Faltam {faltam} confirmações para atingir o consenso. Atualmente: {len(unique_public_keys)}") # Log de progresso do consenso
            return {"message": f"Confirmação recebida para o bloco {block.index}. Faltam {int(faltam)} confirmações para atingir o consenso.", "confirmations_received": len(unique_public_keys), "confirmations_needed": int(2*MASTER_NODES/3)}

    except ValidationError as e:
        logger.error(f"Erro de validação ao confirmar bloco: {e}")
        raise HTTPException(status_code=422, detail=str(e))  # Retorna 422 para erros de validação
    except HTTPException as e:
        raise e  # Re-raise HTTPExceptions para manter o código de status
    except Exception as e:
        logger.error(f"Erro ao confirmar bloco: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno ao confirmar bloco: {e}")

def validate_and_add_block(block: Block, received_block_hash: str, signatures: List[str], public_keys_signers: List[str]) -> bool: # Renamed block_hash to received_block_hash
    """Valida um bloco (novamente, após consenso) e, se válido, adiciona-o à blockchain."""
    try:
        last_block, last_block_hash = get_last_block()

        block.master_node_signatures = signatures # Add signatures to the block object NOW
        computed_block_hash = block.compute_hash() # Compute hash AFTER adding signatures

        logger.debug(f"validate_and_add_block - Validating block index: {block.index}, received_block_hash: {received_block_hash}") # Debug received_block_hash
        logger.debug(f"validate_and_add_block - Computed block hash (with signatures): {computed_block_hash}") # Debug computed_block_hash

        # --- ADDED LOGGING ---
        block_data_validate = { # Reconstruct block_data to log
            "index": block.index,
            "timestamp": block.timestamp,
            "transactions": [tx.dict() for tx in block.transactions],
            "previous_hash": block.previous_hash,
            "nonce": block.nonce,
            "miner": block.miner,
            "master_node_signatures": block.master_node_signatures
        }
        logger.debug(f"validate_and_add_block - block_data for compute_hash: {block_data_validate}") # Log block_data in validation

        # --- Get block_data from the Block object to compare ---
        block_data_received_dict = block.dict() # Get dict from Block object
        block_string_received = json.dumps(block_data_received_dict, sort_keys=True, ensure_ascii=False) # Serialize to JSON string
        block_string_computed = json.dumps(block_data_validate, sort_keys=True, ensure_ascii=False) # Serialize again for comparison

        logger.debug(f"validate_and_add_block - JSON String Received Block   : {block_string_received}") # Log JSON string of received block
        logger.debug(f"validate_and_add_block - JSON String Computed Block  : {block_string_computed}") # Log JSON string of computed block

        if block_string_received != block_string_computed: # COMPARE JSON STRINGS!
            logger.error(f"validate_and_add_block - JSON STRINGS OF BLOCK DATA ARE DIFFERENT! Data Mismatch!") # CRITICAL Data Mismatch Log
        else:
            logger.debug(f"validate_and_add_block - JSON STRINGS OF BLOCK DATA ARE IDENTICAL. Data Matches.") # Data Match Log

        # --- END EVEN MORE DETAILED LOGGING AND DATA COMPARISON ---


        if last_block is None: # Blockchain vazia (genesis)
            if block.index != 0:
                logger.error("Bloco inválido: Blockchain vazia, esperado bloco Genesis.")
                return False
        # Removed redundant block.is_valid(last_block) check here as it's already done in confirm_block route

        if received_block_hash != computed_block_hash: # Compare against received_block_hash
            logger.error(f"Hash do bloco inválido. Recebido: {received_block_hash}, Computado: {computed_block_hash}") # More detailed error log
            logger.error(f"Bloco para validação: {block.dict()}") # Log the block content for inspection
            return False

        if len(signatures) < (2* MASTER_NODES/3):
            logger.error("Número insuficiente de assinaturas para o consenso (em validate_and_add_block).")
            return False


        add_block_to_blockchain(block, computed_block_hash) # Add block with computed_block_hash
        logger.info(f"Bloco {block.index} adicionado à blockchain com {len(signatures)} assinaturas de nós mestres: {public_keys_signers}") # Log with signing keys
        return True

    except Exception as e:
        logger.error(f"Erro ao validar e adicionar bloco (validate_and_add_block): {e}")
        return False

@app.get("/master_nodes")
async def list_master_nodes():
    """Rota para listar as chaves públicas dos nós mestres registrados."""
    logger.info("Rota /master_nodes acessada.")
    return get_master_node_public_keys()

@app.get("/pending_transactions", response_model=List[Transaction])
async def get_pending_tx():
    """Rota para retornar a lista de transações pendentes."""
    logger.info("Rota /pending_transactions acessada.")
    return get_pending_transactions()

@app.get("/balance/{address}")
async def get_balance(address: str):
    """Rota para consultar o saldo de uma carteira."""
    logger.info(f"Rota /balance/{address} acessada.")
    try:
        balance = calculate_balance(address)
        return {"address": address, "balance": balance}
    except Exception as e:
        logger.error(f"Erro ao obter saldo: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/register_wallet")
async def register_wallet(address: str, public_key: str):
    """Rota para registrar uma nova carteira, associando um endereço a uma chave pública."""
    logger.info("Rota /register_wallet acessada.")
    try:
        persist_wallet_key_pair_to_db(address, public_key)
        return {"message": "Carteira registrada com sucesso."}
    except HTTPException as e:
        raise e  # Re-raise HTTPExceptions para manter o código de status
    except Exception as e:
        logger.error(f"Erro ao registrar carteira: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/get_public_key/{address}")
async def get_public_key_route(address: str):
    """Rota para obter a chave pública de um endereço de carteira."""
    logger.info(f"Rota /get_public_key/{address} acessada.")
    try:
        public_key = get_public_key_for_address(address)
        if public_key:
            return {"public_key": public_key}
        else:
            raise HTTPException(status_code=404, detail="Chave pública não encontrada para este endereço.")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Erro ao obter chave pública para {address}: {e}")
        raise HTTPException(status_code=500, detail="Erro ao obter chave pública.")


# ------------------- Inicialização -------------------

def initialize():
    """Função de inicialização do aplicativo, cria tabelas, carrega dados e cria o bloco Genesis se necessário."""
    logger.info("Inicializando...") # Log no inicio da inicialização
    try:
        create_tables()
        load_master_nodes_from_db()
        load_blockchain_from_db()

        global blockchain_df  # Garante que estamos acessando a variável global
        if blockchain_df.empty: # Verificação se o DataFrame está vazio (melhor que len(blockchain_df) == 0 para pandas)
            logger.info("Blockchain DataFrame vazio. Criando bloco Genesis...")
            create_genesis_block()
        else:
            logger.info(f"Blockchain carregada do banco de dados. Tamanho da cadeia: {len(blockchain_df)}") # Log com tamanho da cadeia carregada
        logger.info("Inicialização completa.")
    except Exception as e:
        logger.critical(f"Falha na inicialização: {e}")
        raise  # Re-raise para impedir a inicialização do Uvicorn

# ------------------- Execução do Uvicorn -------------------
if __name__ == "__main__":
    try:
        initialize()
        logger.info(f"Iniciando o servidor Uvicorn na porta {PORT}...")
        uvicorn.run("core:app", host="0.0.0.0", port=PORT, reload=True)
    except Exception as e:
        logger.critical(f"Erro ao iniciar Uvicorn: {e}")
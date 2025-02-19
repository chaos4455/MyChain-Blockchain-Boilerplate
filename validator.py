import hashlib
import json
import time
import requests
import threading
from typing import List, Optional

import logging
import random  # For exponential backoff jitter

# Importe as funções necessárias do core.py
from core import generate_keys, sign_data, is_valid_proof, Block, Transaction, proof_of_work, is_valid_chain, get_blockchain, verify_signature
from pydantic import ValidationError # Import ValidationError for handling block deserialization errors

# Importe as bibliotecas para visualização
import colorama
from colorama import Fore, Back, Style

# Inicializa o Colorama
colorama.init()

# Configuração de Logs
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s') # Mudado para DEBUG
logger = logging.getLogger(__name__)

# Configurações
NODE_COUNT = 3
BASE_PORT = 17223  # A porta do primeiro nó validador
BLOCKCHAIN_PORT = 17222  # A porta da blockchain principal
BLOCKCHAIN_URL = f"http://localhost:{BLOCKCHAIN_PORT}"
DIFFICULTY = 4  # Número de zeros à esquerda necessários no hash
MINING_RATE = 10  # Segundos entre tentativas de mineração
MAX_REGISTRATION_ATTEMPTS = 5  # Número máximo de tentativas de registro
MAX_CONFIRMATION_FAILURES = 12  # Numero máximo de falhas de confirmação antes de abortar
API_RETRY_MAX_ATTEMPTS = 5  # Máximo de tentativas para chamadas à API
API_RETRY_BASE_DELAY = 2  # Delay base em segundos para backoff exponencial na API
API_RETRY_MAX_DELAY = 30  # Delay máximo em segundos para backoff exponencial na API
BLOCK_SYNC_INTERVAL = 30 # Intervalo para sincronização completa da blockchain (segundos)
STARTUP_DELAY = 15 # Delay de inicialização dos validadores (segundos)

# Estatísticas Globais (Sintéticas)
total_transactions_processed = 0
total_blocks_mined = 0
avg_mining_time = 0.0
mining_attempts = 0
failed_registrations = 0  # Contador para falhas de registro
successful_registrations = 0  # Contador para registros bem-sucedidos
block_confirmation_errors = 0  # Contador de erros ao confirmar blocos
api_request_errors = 0  # Contador de erros em requisições à API
invalid_chains_received = 0 # Contador para blockchains inválidas recebidas da API
invalid_pending_transactions = 0 # Contador para transações pendentes inválidas descartadas
full_chain_sync_count = 0 # Contador de sincronizações completas da blockchain

# Lock para proteger o acesso a variáveis globais (threadsafety)
stats_lock = threading.Lock()
blockchain_sync_lock = threading.Lock() # Lock para sincronização da blockchain

def make_api_request(url, method='GET', json_data=None, max_attempts=API_RETRY_MAX_ATTEMPTS, base_delay=API_RETRY_BASE_DELAY, max_delay=API_RETRY_MAX_DELAY, error_detail=""):
    """
    Faz uma requisição à API com retry e backoff exponencial e log de erro aprimorado.

    Args:
        url (str): URL da API.
        method (str): Método HTTP ('GET' ou 'POST').
        json_data (dict, optional): Dados JSON para requisições POST.
        max_attempts (int): Número máximo de tentativas.
        base_delay (int): Delay base para backoff exponencial.
        max_delay (int): Delay máximo para backoff exponencial.
        error_detail (str): Detalhe adicional para logs de erro.

    Returns:
        dict or None: Resposta JSON em caso de sucesso, None em caso de falha após retries.
    """
    global api_request_errors  # Usa o contador global de erros de API

    headers = {'Content-Type': 'application/json'}  # Define o cabeçalho para JSON explicitamente
    log_prefix = f"API Request ({error_detail}):" if error_detail else "API Request:" # Prefixo para logs

    for attempt in range(max_attempts):
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                response = requests.post(url, json=json_data, headers=headers)
            else:
                logger.error(f"🚨 {log_prefix} Método HTTP inválido: {method}")
                return None  # Método inválido

            response.raise_for_status()  # Lança exceção para status de erro HTTP
            return response.json()  # Retorna a resposta JSON se a requisição for bem-sucedida

        except requests.exceptions.RequestException as e:
            delay = min(max_delay, base_delay * (2**attempt) + random.uniform(0, 1)) # Backoff exponencial com jitter
            logger.warning(f"⚠️ {log_prefix} para {url} falhou (Tentativa {attempt + 1}/{max_attempts}): {e}. Retentando em {delay:.2f} segundos...")
            time.sleep(delay)
        except json.JSONDecodeError:
            logger.error(f"🚨 {log_prefix} para {url}: Resposta não é JSON válida.")
            return None # Falha ao decodificar JSON
        except Exception as e: # Captura outras exceções inesperadas
            logger.error(f"🚨 {log_prefix} Erro inesperado na requisição API para {url}: {e}")
            return None

    logger.error(f"❌ {log_prefix} Falha na requisição API para {url} após {max_attempts} tentativas.")
    with stats_lock:
        api_request_errors += 1 # Incrementa contador de erros de API
    return None # Retorna None após todas as tentativas falharem


def register_master_node_if_needed(node_id: int, public_key: str) -> bool:
    """
    Registra o nó mestre na blockchain se ainda não estiver registrado.

    Args:
        node_id (int): ID do nó.
        public_key (str): Chave pública do nó.

    Returns:
        bool: True se registrado com sucesso ou já registrado, False se falhou após tentativas.
    """
    global successful_registrations, failed_registrations

    is_registered = False
    registration_attempts = 0

    while not is_registered and registration_attempts < MAX_REGISTRATION_ATTEMPTS:
        registration_attempts += 1
        error_detail = f"Node {node_id} Registration" # Contexto para logs de erro

        try:
            master_nodes = make_api_request(f"{BLOCKCHAIN_URL}/master_nodes", method='GET', error_detail=error_detail)
            if master_nodes is None: # Falha na requisição API
                logger.warning(f"{Fore.YELLOW}⚠️ Node {node_id}: Falha ao obter lista de nós mestres para registro. Retentando... (Tentativa {registration_attempts}/{MAX_REGISTRATION_ATTEMPTS}){Style.RESET_ALL}")
                continue # Já logou o erro dentro de make_api_request

            if public_key not in master_nodes:
                logger.info(f"{Fore.YELLOW}🔒 Node {node_id}: Não registrado. Registrando... (Tentativa {registration_attempts}/{MAX_REGISTRATION_ATTEMPTS}){Style.RESET_ALL}")
                registration_response = make_api_request(f"{BLOCKCHAIN_URL}/register_node", method='POST', json_data={"public_key": public_key}, error_detail=error_detail)
                if registration_response and registration_response.get("message") == "Nó mestre registrado com sucesso.":
                    with stats_lock:
                        successful_registrations += 1
                    logger.info(f"{Fore.GREEN}✅ Node {node_id}: Registrado com sucesso!{Style.RESET_ALL}")
                    is_registered = True
                else:
                    logger.error(f"{Fore.RED}🚨 Node {node_id}: Falha ao registrar nó mestre (Tentativa {registration_attempts}/{MAX_REGISTRATION_ATTEMPTS}). Resposta inesperada: {registration_response}{Style.RESET_ALL}")
                    with stats_lock:
                        failed_registrations += 1
            else:
                logger.info(f"{Fore.GREEN}✅ Node {node_id}: Já registrado.{Style.RESET_ALL}")
                is_registered = True
                break # Sai do loop se já registrado

        except Exception as e: # Captura erros gerais, logs mais genéricos aqui
            logger.error(f"{Fore.RED}🚨 Node {node_id}: Erro inesperado ao registrar nó mestre (Tentativa {registration_attempts}/{MAX_REGISTRATION_ATTEMPTS}): {e}{Style.RESET_ALL}")
            with stats_lock:
                failed_registrations += 1
            time.sleep(MINING_RATE * 2) # Espera mais em caso de erro inesperado, antes de retentar

    if not is_registered:
        logger.error(f"{Fore.RED}❌ Node {node_id}: Falha ao registrar nó mestre após {MAX_REGISTRATION_ATTEMPTS} tentativas.{Style.RESET_ALL}")
        return False
    return True

def sync_blockchain_from_api(node_id: int) -> Optional[List[Block]]:
    """
    Sincroniza a blockchain completa da API.

    Args:
        node_id (int): ID do nó que está sincronizando.

    Returns:
        Optional[List[Block]]: A blockchain sincronizada como lista de objetos Block, ou None em caso de falha.
    """
    global full_chain_sync_count, invalid_chains_received # Access global counters

    logger.info(f"{Fore.CYAN}🔄 Node {node_id}: Sincronizando blockchain completa da API...{Style.RESET_ALL}")
    error_detail = f"Node {node_id} Full Chain Sync" # Contexto para logs de erro

    blockchain_json = make_api_request(f"{BLOCKCHAIN_URL}/blockchain", method='GET', error_detail=error_detail)
    if blockchain_json is None:
        logger.warning(f"⚠️ Node {node_id}: Falha ao obter blockchain para sincronização.")
        return None

    try:
        blockchain = [Block(**block_data) for block_data in blockchain_json] # Desserializa para objetos Block
    except ValidationError as e:
        logger.error(f"{Fore.RED}🚨 Node {node_id}: Erro de validação ao desserializar blockchain da API durante sincronização: {e}{Style.RESET_ALL}")
        return None

    if not is_valid_chain(blockchain): # Valida a cadeia sincronizada
        logger.error(f"{Fore.RED}🚨 Node {node_id}: Blockchain sincronizada da API é inválida! Descartando.{Style.RESET_ALL}")
        with stats_lock:
            invalid_chains_received += 1
        return None

    with stats_lock:
        full_chain_sync_count += 1 # Incrementa contador de sincronizações bem-sucedidas
    logger.info(f"{Fore.GREEN}✅ Node {node_id}: Blockchain sincronizada com sucesso. Chain size: {len(blockchain)} blocks.{Style.RESET_ALL}")
    return blockchain # Retorna a blockchain sincronizada

def get_latest_blockchain_data(node_id: int, blockchain_cache: dict) -> tuple[Optional[List[Block]], Optional[str], Optional[int]]:
    """
    Obtém os dados mais recentes da blockchain (blockchain completa, último hash e index) usando cache.

    Args:
        node_id (int): ID do nó.
        blockchain_cache (dict): Cache da blockchain para este nó.

    Returns:
        tuple: (blockchain, previous_hash, last_block_index) ou (None, None, None) em caso de erro.
    """
    if blockchain_cache and 'blockchain' in blockchain_cache and 'last_update' in blockchain_cache:
        if time.time() - blockchain_cache['last_update'] <= BLOCK_SYNC_INTERVAL:
            logger.debug(f"Node {node_id}: Usando blockchain do cache.")
            blockchain = blockchain_cache['blockchain']
            if blockchain:
                last_block = blockchain[-1]
                previous_hash = last_block.hash
                index = last_block.index + 1
            else: # Blockchain vazia
                previous_hash = "0"
                index = 0
            return blockchain, previous_hash, index


    # Se o cache estiver vencido ou vazio, sincroniza a blockchain completa
    with blockchain_sync_lock: # Garante que apenas um nó sincronize por vez
        blockchain = sync_blockchain_from_api(node_id) # Sincroniza a blockchain completa da API
        if blockchain:
             blockchain_cache['blockchain'] = blockchain # Atualiza o cache com a blockchain completa
             blockchain_cache['last_update'] = time.time() # Atualiza o timestamp do cache
             logger.debug(f"Node {node_id}: Blockchain cache atualizado.")


    if blockchain:
        last_block = blockchain[-1]
        previous_hash = last_block.hash # Usa o hash do objeto Block diretamente
        index = last_block.index + 1
    else: # Blockchain vazia or falha na sincronização
        logger.warning(f"⚠️ Node {node_id}: Blockchain vazia detectada after sync.") # More specific warning
        logger.info(f"ℹ️ Node {node_id}: Starting with empty blockchain - proceeding to mine Genesis (or next block).") # Info log
        return [], "0", 0 # Return empty blockchain, Genesis previous_hash, index 0


    return blockchain, previous_hash, index


def get_pending_transactions_from_api(node_id: int) -> Optional[List[Transaction]]: # Mudança no tipo de retorno para List[Transaction]
    """
    Obtém as transações pendentes da API e as valida.

    Args:
        node_id (int): ID do nó.

    Returns:
        Optional[List[Transaction]]: Lista de transações pendentes validadas ou None em caso de erro.
    """
    global invalid_pending_transactions # Access global counter

    error_detail = f"Node {node_id} Pending TX Fetch" # Contexto para logs de erro
    pending_transactions_json = make_api_request(f"{BLOCKCHAIN_URL}/pending_transactions", method='GET', error_detail=error_detail)

    if pending_transactions_json is None: # Falha na requisição API já tratada em make_api_request
        logger.warning(f"⚠️ Node {node_id}: Falha ao obter transações pendentes da API.")
        return None

    valid_transactions = []
    if pending_transactions_json:
        for tx_data in pending_transactions_json:
            try:
                transaction = Transaction(**tx_data) # Cria objeto Transaction
                if verify_transaction_signature_validator(transaction): # Valida a transação (usando função local!)
                    valid_transactions.append(transaction)
                else:
                    logger.warning(f"{Fore.YELLOW}⚠️ Node {node_id}: Transação pendente inválida (assinatura falhou), descartando: {transaction}{Style.RESET_ALL}")
                    with stats_lock:
                        invalid_pending_transactions += 1 # Increment invalid transaction counter

            except ValidationError as e:
                logger.error(f"{Fore.RED}🚨 Node {node_id}: Erro de validação ao desserializar transação pendente da API, descartando: {e} Data: {tx_data}{Style.RESET_ALL}")
                with stats_lock:
                    invalid_pending_transactions += 1 # Increment invalid transaction counter
            except Exception as e:
                logger.error(f"{Fore.RED}🚨 Node {node_id}: Erro inesperado ao processar transação pendente, descartando. Erro: {e}, Data: {tx_data}{Style.RESET_ALL}")
                with stats_lock:
                    invalid_pending_transactions += 1 # Increment invalid transaction counter

    return valid_transactions # Retorna apenas as transações validas

def verify_transaction_signature_validator(transaction: Transaction) -> bool:
    """
    Verifica a assinatura de uma transação (função local do validador para evitar dependência circular).
    **IMPORTANTE:** Duplica a lógica de verificação de assinatura de core.py para isolamento.
    """
    try:
        # Se a transação for do Genesis, ignore a verificação
        if transaction.sender == "Genesis": # Usar GENESIS_ADDRESS se definido como global em validator.py
            return True

        # Prepare os dados para verificação (sem a assinatura)
        data = f"{transaction.sender}{transaction.recipient}{transaction.amount}"
        signature_bytes = bytes.fromhex(transaction.signature)

        # **Requisita a chave publica da API** - Validador busca chave publica direto da API para maior segurança
        error_detail = f"Node - {transaction.sender} Public Key Fetch" # Contexto para logs de erro
        public_key_pem_response = make_api_request(f"{BLOCKCHAIN_URL}/get_public_key/{transaction.sender}", method='GET', error_detail=error_detail) # Rota da API para buscar chave publica por address

        if not public_key_pem_response or not public_key_pem_response.get('public_key'):
            logger.warning(f"Chave pública não encontrada na API para o endereço: {transaction.sender}")
            return False
        public_key_pem = public_key_pem_response['public_key']


        return verify_signature(public_key_pem, signature_bytes, data) # Reutiliza verify_signature (já importada de core.py)
    except Exception as e:
        logger.error(f"Erro ao verificar assinatura da transação no validador: {e}")
        return False


def construct_and_mine_block(node_id: int, index: int, timestamp: float, pending_transactions: List[Transaction], previous_hash: str, miner_address: str) -> Block:
    """
    Constrói e minera um novo bloco.

    Args:
        node_id (int): ID do nó.
        index (int): Índice do bloco.
        timestamp (float): Timestamp do bloco.
        pending_transactions (List[Transaction]): Transações pendentes.
        previous_hash (str): Hash do bloco anterior.
        miner_address (str): Endereço do minerador.

    Returns:
        Block: Bloco minerado.
    """
    start_time = time.time()

    new_block = Block(
        index=index,
        timestamp=timestamp,
        transactions=pending_transactions,
        previous_hash=previous_hash,
        nonce=0,
        miner=miner_address,
        master_node_signatures=[]
    )

    logger.info(f"{Fore.BLUE}⛏️ Node {node_id}: Minerando bloco {new_block.index}...{Style.RESET_ALL}")

    # Proof of Work (Mineração)
    nonce = proof_of_work(new_block) # <--- Get the nonce from PoW
    new_block.nonce = nonce # <--- Set the nonce in the block

    end_time = time.time()
    mining_time = end_time - start_time
    logger.info(f"Node {node_id}: Bloco {new_block.index} minerado em {mining_time:.2f} segundos. Nonce: {new_block.nonce}")

    with stats_lock:
        global avg_mining_time, total_blocks_mined, mining_attempts # Declara globais aqui
        mining_attempts += 1
        total_blocks_mined += 1
        avg_mining_time = (avg_mining_time * (total_blocks_mined - 1) + mining_time) / total_blocks_mined if total_blocks_mined > 0 else mining_time # Calcula média móvel

    return new_block

def sign_and_confirm_block(node_id: int, block: Block, block_hash: str, private_key: str, public_key: str) -> bool:
    """
    Assina e envia o bloco minerado para confirmação.

    Args:
        node_id (int): ID do nó.
        block (Block): Bloco minerado.
        block_hash (str): Hash do bloco.
        private_key (str): Chave privada do nó.
        public_key (str): Chave pública do nó.

    Returns:
        bool: True se a confirmação for bem-sucedida, False se falhar.
    """
    global block_confirmation_errors

    try:
        signature = sign_data(private_key, block_hash) # Assina o hash, não o bloco inteiro
    except Exception as e: # Captura erros ao assinar
        logger.error(f"{Fore.RED}🚨 Node {node_id}: Erro ao assinar o bloco: {e}{Style.RESET_ALL}")
        return False

    confirmation_data = {
        "block": block.dict(), # Envia o bloco completo
        "block_hash": block_hash, # Envia o hash separadamente (redundante, mas claro)
        "signature": signature.hex(),
        "public_key": public_key
    }

    logger.debug(f"Node {node_id}: Hash before confirmation send: {block_hash}") # Log hash BEFORE sending confirmation
    logger.debug(f"Node {node_id}: Block before confirmation send: {confirmation_data['block']}") # Log block data BEFORE sending confirmation

    error_detail = f"Node {node_id} Block Confirmation" # Contexto para logs de erro
    confirmation_response = make_api_request(f"{BLOCKCHAIN_URL}/confirm_block", method='POST', json_data=confirmation_data, error_detail=error_detail)
    if confirmation_response and confirmation_response.get("message") and "adicionado à blockchain com consenso" in confirmation_response.get("message"):
        logger.info(f"{Fore.GREEN}✅ Node {node_id}: Bloco {block.index} confirmado e adicionado à blockchain: {confirmation_response}{Style.RESET_ALL}")
        return True # Confirmação bem-sucedida
    else:
        error_detail_resp = confirmation_response.get("detail") if confirmation_response and confirmation_response.get("detail") else "Resposta da API sem detalhes"
        logger.error(f"{Fore.RED}🚨 Node {node_id}: Erro ao confirmar bloco. Resposta da API: {confirmation_response}. Detalhes: {error_detail_resp}{Style.RESET_ALL}")
        with stats_lock:
            block_confirmation_errors += 1
        return False # Falha na confirmação

def create_and_mine_block_for_node(node_id: int, port: int, private_key: str, public_key: str, blockchain_cache: dict):
    """
    Função principal para o loop de mineração de um nó validador.

    Args:
        node_id (int): ID do nó.
        port (int): Porta do nó (não usada diretamente aqui, mas pode ser útil para logs ou extensões futuras).
        private_key (str): Chave privada do nó.
        public_key (str): Chave pública do nó.
        blockchain_cache (dict): Cache local da blockchain para este nó.
    """
    global successful_registrations, failed_registrations, total_transactions_processed, total_blocks_mined, avg_mining_time, mining_attempts, block_confirmation_errors, invalid_chains_received, invalid_pending_transactions # Inclui novos contadores globais

    miner_address = f"Node{node_id}"  # Identificador do minerador
    logger.info(f"{Fore.GREEN}✨ Node {node_id}: Iniciando mineração na porta {port}...{Style.RESET_ALL}")

    confirmation_failures_local = 0 # Contador local de falhas de confirmação
    time.sleep(STARTUP_DELAY) # ADD STARTUP DELAY HERE - Wait before starting mining loop


    if not register_master_node_if_needed(node_id, public_key): # Registra e sai se falhar repetidamente
        logger.error(f"{Fore.RED}❌ Node {node_id}: Falha ao registrar nó mestre. Abortando mineração.{Style.RESET_ALL}")
        return

    while True:
        blockchain, previous_hash, index = get_latest_blockchain_data(node_id, blockchain_cache) # Obtém dados da blockchain (usando cache)

        if blockchain is None: # Falha ao obter blockchain, espera e retenta
            logger.warning(f"⚠️ Node {node_id}: Falha ao obter dados da blockchain. Esperando {MINING_RATE} segundos e retentando...")
            time.sleep(MINING_RATE)
            continue # Volta para o início do loop


        pending_transactions = get_pending_transactions_from_api(node_id) # Obtém transações pendentes
        if pending_transactions is None: # Falha ao obter transações, espera e retenta
            logger.warning(f"⚠️ Node {node_id}: Falha ao obter transações pendentes. Esperando {MINING_RATE} segundos e retentando...")
            time.sleep(MINING_RATE)
            continue # Volta para o início do loop

        if not pending_transactions:
            logger.info(f"😴 {Fore.YELLOW}Node {node_id}: Nenhuma transação pendente válida. Esperando...{Style.RESET_ALL}")
            time.sleep(MINING_RATE)
            continue # Volta para o início do loop se não houver transações

        with stats_lock:
            total_transactions_processed += len(pending_transactions) # Atualiza contador global de transações processadas

        try:
            new_block = construct_and_mine_block(node_id, index, time.time(), pending_transactions, previous_hash, miner_address) # Constrói e minera bloco
            block_hash = new_block.compute_hash() # Calcula o hash do bloco MINERADO (agora)

            if sign_and_confirm_block(node_id, new_block, block_hash, private_key, public_key): # Assina e confirma bloco
                confirmation_failures_local = 0 # Reseta contador de falhas de confirmação em caso de sucesso
            else:
                confirmation_failures_local += 1 # Incrementa se falha na confirmação
        except Exception as e: # Captura exceções durante a mineração ou confirmação (PoW, assinatura, etc.)
            logger.error(f"{Fore.RED}🚨 Node {node_id}: Erro durante mineração ou confirmação do bloco: {e}{Style.RESET_ALL}")
            confirmation_failures_local += 1 # Incrementa falhas em caso de erro geral
            with stats_lock:
                block_confirmation_errors += 1 # Incrementa contador global de erros de confirmação


        if confirmation_failures_local > MAX_CONFIRMATION_FAILURES: # Aborta se exceder o limite de falhas de confirmação
            logger.critical(f"{Fore.RED}🔥 Node {node_id}: Excedeu o número máximo de falhas de confirmação ({MAX_CONFIRMATION_FAILURES}). Abortando mineração.{Style.RESET_ALL}")
            break # Sai do loop de mineração se muitas falhas

        time.sleep(MINING_RATE) # Espera antes da próxima iteração

# Iniciar os nós validadores em threads
if __name__ == "__main__":
    # Cache da blockchain para cada nó
    blockchain_caches = {}
    # Gerar chaves RSA para cada nó
    keys = [generate_keys() for _ in range(NODE_COUNT)]
    threads = []
    for i in range(NODE_COUNT):
        port = BASE_PORT + i
        node_id = i + 1
        private_key, public_key = keys[i]
        blockchain_caches[node_id] = {} # Inicializa cache para o nó
        thread = threading.Thread(target=create_and_mine_block_for_node, args=(node_id, port, private_key, public_key, blockchain_caches[node_id])) # Passa o cache para a thread
        threads.append(thread)
        thread.start()

    # Função para exibir as métricas
    def display_metrics():
        while True:
            # Access stats
            with stats_lock:
                global total_blocks_mined, avg_mining_time, mining_attempts, block_confirmation_errors, successful_registrations, failed_registrations, api_request_errors, invalid_chains_received, invalid_pending_transactions, full_chain_sync_count # Inclui novos contadores globais
                logger.info(f"\n{Fore.CYAN}📊 Blockchain Metrics:{Style.RESET_ALL}")
                logger.info(f"{Fore.MAGENTA}   Total Blocks Mined: {total_blocks_mined}{Style.RESET_ALL}")
                logger.info(f"{Fore.MAGENTA}   Total Transactions Processed: {total_transactions_processed}{Style.RESET_ALL}")
                logger.info(f"{Fore.MAGENTA}   Avg. Mining Time: {avg_mining_time:.2f} s{Style.RESET_ALL}")
                logger.info(f"{Fore.MAGENTA}   Total Mining Attempts: {mining_attempts}{Style.RESET_ALL}")
                logger.info(f"{Fore.RED}   Failed Registrations: {failed_registrations}{Style.RESET_ALL}")
                logger.info(f"{Fore.GREEN}   Successful Registrations: {successful_registrations}{Style.RESET_ALL}")
                logger.info(f"{Fore.RED}   Block Confirmation Errors: {block_confirmation_errors}{Style.RESET_ALL}")
                logger.info(f"{Fore.YELLOW}   API Request Errors: {api_request_errors}{Style.RESET_ALL}") # Nova métrica para erros de API
                logger.info(f"{Fore.RED}   Invalid Chains Received: {invalid_chains_received}{Style.RESET_ALL}") # Nova métrica para cadeias inválidas
                logger.info(f"{Fore.RED}   Invalid Pending Transactions: {invalid_pending_transactions}{Style.RESET_ALL}") # Nova métrica para transações pendentes inválidas
                logger.info(f"{Fore.CYAN}   Full Chain Syncs: {full_chain_sync_count}{Style.RESET_ALL}\n") # Nova métrica para full syncs

            time.sleep(5.0)  # Update metrics display every 5 segundos (menos frequente)

    # Create a thread to display metrics in real-time
    metrics_thread = threading.Thread(target=display_metrics)
    metrics_thread.daemon = True  # Allow the thread to exit when the program exits
    metrics_thread.start()

    for thread in threads:
        thread.join() # Keep the main thread alive
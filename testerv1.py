import requests
import time
import hashlib
import json
import os
import yaml  # Import PyYAML
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from rich.console import Console
from rich.rule import Rule
from rich.progress import Progress
from rich.text import Text
from rich.panel import Panel
from rich.style import Style

# Initialize Rich Console
console = Console(force_terminal=True, color_system="truecolor")

# Endereço da API da blockchain
API_URL = "http://localhost:17222"  # Ajuste se necessário

# Nome dos arquivos para salvar os dados
WALLETS_FILE_JSON = "wallets_v2.json"
WALLETS_FILE_YAML = "wallets_v2.yaml"
TRANSACTIONS_FILE_JSON = "transactions_v2.json"
TRANSACTIONS_FILE_YAML = "transactions_v2.yaml"

def generate_keys():
    """Gera um par de chaves RSA (privada e pública)."""
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

def load_key(key_string: str, private=False):
    """Carrega uma chave RSA (privada ou pública) a partir de uma string."""
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

def sign_data(private_key_pem: str, data: str) -> bytes:
    """Assina dados com a chave privada."""
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

def register_wallet(address, public_key):
    """Registra uma carteira na blockchain."""
    console.print(f":key: [bold blue]Registering wallet[/bold blue] [bold magenta]{address}[/bold magenta]...", end=" ")
    try:
        response = requests.post(f"{API_URL}/register_wallet?address={address}&public_key={public_key}")
        response.raise_for_status()
        console.print(f"[bold green]Success[/bold green] :check_mark_button:")
        return True
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error[/bold red] :cross_mark: - [italic]{e}[/italic]")
        return False

def create_transaction(sender_private_key, sender_address, recipient_address, amount):
    """Cria e envia uma transação assinada para a blockchain."""
    console.print(f":arrow_right: [bold cyan]Creating transaction[/bold cyan] from [bold magenta]{sender_address}[/bold magenta] to [bold magenta]{recipient_address}[/bold magenta] amount [bold green]{amount}[/bold green]...", end=" ")

    # Se for a transação Genesis, não assina
    if sender_address == "Genesis":
        signature = ""
    else:
        data = f"{sender_address}{recipient_address}{amount}"
        signature = sign_data(sender_private_key, data).hex()

    transaction_data = {
        "sender": sender_address,
        "recipient": recipient_address,
        "amount": amount,
        "signature": signature
    }

    try:
        response = requests.post(f"{API_URL}/transaction", json=transaction_data)
        response.raise_for_status()
        console.print(f"[bold green]Sent[/bold green] :check_mark_button:")
        return transaction_data
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error[/bold red] :cross_mark: - [italic]{e}[/italic]")
        return None

def wait_for_block():
    """Espera até que um novo bloco seja minerado com Rich Progress Bar."""
    console.print("[bold yellow]:hourglass: Waiting for a new block to be mined...[/bold yellow]")
    with Progress(transient=True) as progress:
        task_id = progress.add_task("[cyan]Mining...", total=None)
        initial_chain = requests.get(f"{API_URL}/blockchain").json()
        initial_length = len(initial_chain)
        while True:
            current_chain = requests.get(f"{API_URL}/blockchain").json()
            if len(current_chain) > initial_length:
                progress.update(task_id, advance=100, total=100, visible=False)  # Finish progress bar
                break
            time.sleep(1) # Reduced sleep for faster feedback
    console.print("[bold green]:sparkles: New block mined![/bold green]")

def load_wallets():
    """Carrega as carteiras do arquivo JSON e YAML."""
    wallets_json = {}
    wallets_yaml = {}
    try:
        with open(WALLETS_FILE_JSON, 'r', encoding='utf-8') as f_json:
            wallets_json = json.load(f_json)
    except FileNotFoundError:
        pass # Arquivo JSON não encontrado, não é um erro fatal
    except json.JSONDecodeError:
        console.print(f"[bold yellow]:warning_sign: Warning:[/bold yellow] Error decoding [bold magenta]{WALLETS_FILE_JSON}[/bold magenta]. Creating a new one.")

    try:
        with open(WALLETS_FILE_YAML, 'r', encoding='utf-8') as f_yaml:
            wallets_yaml = yaml.safe_load(f_yaml) or {} # yaml.safe_load can return None
    except FileNotFoundError:
        pass # Arquivo YAML não encontrado, não é um erro fatal
    except yaml.YAMLError:
        console.print(f"[bold yellow]:warning_sign: Warning:[/bold yellow] Error decoding [bold magenta]{WALLETS_FILE_YAML}[/bold magenta]. Creating a new one.")

    # Merge wallets, JSON takes precedence if keys overlap
    wallets = {**wallets_yaml, **wallets_json} # Merge dicts, JSON overwrites YAML in case of overlap

    return wallets

def save_wallets(wallets):
    """Salva as carteiras nos arquivos JSON e YAML com UTF-8 encoding."""
    with open(WALLETS_FILE_JSON, 'w', encoding='utf-8') as f_json:
        json.dump(wallets, f_json, indent=4, ensure_ascii=False) # ensure_ascii=False for UTF-8
    console.print(f":floppy_disk: Wallets saved to [bold magenta]{WALLETS_FILE_JSON}[/bold magenta]")

    with open(WALLETS_FILE_YAML, 'w', encoding='utf-8') as f_yaml:
        yaml.dump(wallets, f_yaml, indent=2, allow_unicode=True) # allow_unicode=True for UTF-8
    console.print(f":floppy_disk: Wallets saved to [bold magenta]{WALLETS_FILE_YAML}[/bold magenta]")

def save_transactions_data(transactions, filename_json, filename_yaml):
    """Salva os dados das transações em JSON e YAML com UTF-8."""
    with open(filename_json, 'w', encoding='utf-8') as f_json:
        json.dump(transactions, f_json, indent=4, ensure_ascii=False)
    console.print(f":floppy_disk: Transactions saved to [bold magenta]{filename_json}[/bold magenta]")

    with open(filename_yaml, 'w', encoding='utf-8') as f_yaml:
        yaml.dump(transactions, f_yaml, indent=2, allow_unicode=True)
    console.print(f":floppy_disk: Transactions saved to [bold magenta]{filename_yaml}[/bold magenta]")


if __name__ == "__main__":
    console.rule(Text("Starting Tester v2 - Improved & Corrected", style="bold blue")) # More descriptive title

    # Carrega as carteiras existentes
    wallets = load_wallets()
    console.print(":file_folder: [bold]Loaded existing wallets[/bold] from JSON and YAML (if available).")

    transactions_genesis = []
    transactions_test = []

    # 1. Gerar e registrar as carteiras
    with console.status("[bold green]Creating and Registering Wallets..."):
        if "Carteira1" not in wallets:
            console.log(Panel(Text("Creating Carteira1", style="bold magenta"), border_style="blue", padding=(1, 2)))
            private_key_1, public_key_1 = generate_keys()
            address_1 = "Carteira1"  #Nome da Carteira
            if register_wallet(address_1, public_key_1):
                wallets[address_1] = {"public_key": public_key_1, "private_key": private_key_1}
            else:
                console.print(f"[bold red]:cross_mark: Failed to register Carteira1. Exiting.[/bold red]")
                exit()
        else:
            console.log(Panel(Text("Carteira1 already exists", style="bold magenta"), border_style="blue", padding=(1, 2)))
            address_1 = "Carteira1"
            private_key_1 = wallets[address_1]["private_key"] #Carrega chave privada

        if "Carteira2" not in wallets:
            console.log(Panel(Text("Creating Carteira2", style="bold magenta"), border_style="blue", padding=(1, 2)))
            private_key_2, public_key_2 = generate_keys()
            address_2 = "Carteira2" #Nome da Carteira
            if register_wallet(address_2, public_key_2):
                wallets[address_2] = {"public_key": public_key_2, "private_key": private_key_2}
            else:
                console.print(f"[bold red]:cross_mark: Failed to register Carteira2. Exiting.[/bold red]")
                exit()
        else:
            console.log(Panel(Text("Carteira2 already exists", style="bold magenta"), border_style="blue", padding=(1, 2)))
            address_2 = "Carteira2"
            private_key_2 = wallets[address_2]["private_key"] #Carrega chave privada
    # Salva as carteiras
    save_wallets(wallets)

    # 2.  Criação das transações Genesis
    console.rule(Text("Genesis Transactions", style="bold cyan"))
    with console.status("[bold green]Creating Genesis Transactions..."):
        genesis_tx1_data = create_transaction("", "Genesis", address_1, 10)  # Doa 10 Tokens
        if genesis_tx1_data:
            transactions_genesis.append(genesis_tx1_data)
        else:
            console.print("[bold red]:cross_mark: Failed to create Genesis transaction 1.[/bold red]")

        genesis_tx2_data = create_transaction("", "Genesis", address_2, 10)  # Doa 10 Tokens
        if genesis_tx2_data:
            transactions_genesis.append(genesis_tx2_data)
        else:
            console.print("[bold red]:cross_mark: Failed to create Genesis transaction 2.[/bold red]")

    # 3. Aguardar a mineração do bloco Genesis e transações de criação
    wait_for_block()

    # 4. Fazer as transações de teste
    console.rule(Text("Test Transactions", style="bold cyan"))
    with console.status("[bold green]Creating Test Transactions..."):
        test_tx1_data = create_transaction(private_key_1, address_1, address_2, 5)
        if test_tx1_data:
            transactions_test.append(test_tx1_data)
            wait_for_block() # Aguarda a mineração da primeira transação
        else:
            console.print("[bold red]:cross_mark: Failed to create Test transaction 1.[/bold red]")

        test_tx2_data = create_transaction(private_key_2, address_2, address_1, 2)
        if test_tx2_data:
            transactions_test.append(test_tx2_data)
            wait_for_block()  # Aguarda a mineração da segunda transação
        else:
            console.print("[bold red]:cross_mark: Failed to create Test transaction 2.[/bold red]")


    # 5. Salvar dados das transações
    console.rule(Text("Saving Transaction Data", style="bold cyan"))
    all_transactions = {
        "genesis_transactions": transactions_genesis,
        "test_transactions": transactions_test
    }
    save_transactions_data(all_transactions, TRANSACTIONS_FILE_JSON, TRANSACTIONS_FILE_YAML)


    console.rule(Rule(Text("Process Completed!", style="bold green")))
    console.print(Panel(Text(":trophy: Tester v2 finished successfully! :trophy:", style="bold green"), border_style="green", padding=(1, 2)))
import os
import glob
import re

def analisar_arquivo_py(caminho_arquivo):
    """
    Analisa um arquivo Python e retorna informações sobre ele.

    Args:
        caminho_arquivo (str): O caminho para o arquivo Python.

    Returns:
        dict: Um dicionário contendo informações como nome do arquivo, tamanho,
              número de linhas e o código fonte.  Retorna None se o arquivo não existir.
    """
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as arquivo:
            codigo_fonte = arquivo.read()
            numero_linhas = len(codigo_fonte.splitlines())
            tamanho_bytes = os.path.getsize(caminho_arquivo)  # Tamanho em bytes

            return {
                'nome_arquivo': os.path.basename(caminho_arquivo),
                'tamanho_bytes': tamanho_bytes,
                'numero_linhas': numero_linhas,
                'codigo_fonte': codigo_fonte,
            }
    except FileNotFoundError:
        print(f"Arquivo não encontrado: {caminho_arquivo}")
        return None
    except Exception as e:
        print(f"Erro ao ler o arquivo {caminho_arquivo}: {e}")
        return None

def gerar_documentacao(caminho_raiz='.'):
    """
    Gera um arquivo de documentação "codigo_fonte.txt" que lista todos os arquivos
    Python na raiz especificada (e suas subpastas), juntamente com informações
    sobre cada arquivo e seu código fonte.  Também tenta criar uma documentação
    básica a partir de docstrings.

    Args:
        caminho_raiz (str): O caminho para o diretório raiz a ser analisado.
                             O padrão é o diretório atual ('.').
    """

    arquivos_py = glob.glob(os.path.join(caminho_raiz, '**/*.py'), recursive=True)

    with open('codigo_fonte.txt', 'w', encoding='utf-8') as arquivo_saida:
        # Cabeçalho do arquivo de documentação
        arquivo_saida.write("==================================================\n")
        arquivo_saida.write("              DOCUMENTAÇÃO CÓDIGO FONTE              \n")
        arquivo_saida.write("==================================================\n\n")
        arquivo_saida.write(f"Gerado em: {datetime.datetime.now()}\n")
        arquivo_saida.write(f"Diretório raiz analisado: {caminho_raiz}\n\n")

        for caminho_arquivo in arquivos_py:
            info_arquivo = analisar_arquivo_py(caminho_arquivo)

            if info_arquivo:
                arquivo_saida.write("--------------------------------------------------\n")
                arquivo_saida.write(f"Nome do arquivo: {info_arquivo['nome_arquivo']}\n")
                arquivo_saida.write(f"Caminho completo: {caminho_arquivo}\n") #adicionado caminho completo
                arquivo_saida.write(f"Tamanho (bytes): {info_arquivo['tamanho_bytes']}\n")
                arquivo_saida.write(f"Número de linhas: {info_arquivo['numero_linhas']}\n")
                arquivo_saida.write("--------------------------------------------------\n\n")

                arquivo_saida.write("CÓDIGO FONTE:\n")
                arquivo_saida.write("```python\n")
                arquivo_saida.write(info_arquivo['codigo_fonte'])
                arquivo_saida.write("\n```\n\n")

                # Extrair e adicionar docstrings (documentação básica)
                arquivo_saida.write("DOCUMENTAÇÃO (Docstrings):\n")
                docstrings = extrair_docstrings(info_arquivo['codigo_fonte'])
                if docstrings:
                    for nome, docstring in docstrings.items():
                        arquivo_saida.write(f"  {nome}:\n")
                        arquivo_saida.write(f"    {docstring.strip()}\n")  # Remover espaços extras
                else:
                    arquivo_saida.write("  Nenhuma docstring encontrada.\n")
                arquivo_saida.write("\n")
            else:
                arquivo_saida.write(f"Erro ao processar o arquivo: {caminho_arquivo}\n\n")

        arquivo_saida.write("==================================================\n")
        arquivo_saida.write("              FIM DA DOCUMENTAÇÃO                   \n")
        arquivo_saida.write("==================================================\n")


def extrair_docstrings(codigo_fonte):
    """
    Extrai docstrings de funções e classes do código fonte.

    Args:
        codigo_fonte (str): O código fonte Python.

    Returns:
        dict: Um dicionário onde as chaves são os nomes das funções/classes
              e os valores são as suas docstrings correspondentes.
              Retorna um dicionário vazio se nenhuma docstring for encontrada.
    """
    docstrings = {}
    # Padrão para encontrar definições de funções e classes com docstrings
    padrao = r"(def|class)\s+(\w+)\s*\(.*?\):\s*(\"\"\"(.*?)\"\"\"|'''(.*?)''')"
    correspondencias = re.findall(padrao, codigo_fonte, re.DOTALL)  # re.DOTALL para multilinhas

    for tipo, nome, _, docstring_aspas_triplas, docstring_pluma in correspondencias:
        docstring = docstring_aspas_triplas or docstring_pluma  # Escolher qual docstring usar
        docstrings[f"{tipo} {nome}"] = docstring

    return docstrings


if __name__ == "__main__":
    import datetime  # Importar datetime aqui para usar dentro da função gerar_documentacao

    # Chame a função para gerar a documentação, definindo o diretório raiz
    # Se quiser analisar a pasta atual, use apenas gerar_documentacao()
    gerar_documentacao() # analisa a pasta atual
    #gerar_documentacao('/caminho/para/sua/pasta') # Substitua pelo caminho real, se necessário

    print("Documentação gerada em 'codigo_fonte.txt'")
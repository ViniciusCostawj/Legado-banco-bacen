# 💸 API SPI & DICT - Banco Central

[![Made with FastAPI](https://img.shields.io/badge/Made%20with-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![License](https://img.shields.io/badge/Licença-Interna-lightgrey)
![Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-yellow)

API **FastAPI** para integração com o **SPI** e **DICT** do Banco Central.  
Realiza autenticação mTLS, assinatura digital XMLDSig e envio de transações PIX seguras, além de consultas de chaves DICT, garantindo comunicação criptografada e validação de identidades financeiras.

---

## ⚙️ Funcionalidades

- 🔐 Conexão segura com o SPI via mTLS  
- 💸 Envio de transações PIX assinadas digitalmente  
- 🗝️ Consulta de chaves no diretório DICT  
- 🧾 Geração e assinatura de XML padrão `pacs.008`

---

## 🚀 Executando o Projeto

### 1️⃣ Requisitos
- Python 3.11+
- Certificado `.pfx` válido (Bacen ou homologação)
- Arquivo `.env` com:
  ```env
  BACEN_PFX_PASSWORD=sua_senha
  
2️⃣ Instalação
bash
Copiar código
pip install fastapi | httpx | cryptography | python-dotenv | signxml | lxml | uvicorn


3️⃣ Estrutura recomendada
bash
Copiar código
projeto_spi/
├── main.py
├── .env
├── certificados/
│   └── teste.pfx
└── requirements.txt


4️⃣ Executar servidor
bash
Copiar código

$env:BACEN_PFX_PASSWORD = "sua_senha_secreta_aqui"

uvicorn main:app --reload


🧠 Endpoints Principais

🔹 Conectar ao SPI

Rota: POST /api/conectar

Exemplo:

bash
Copiar código
curl -X POST http://127.0.0.1:8000/api/conectar \

  -H "Content-Type: application/json" \
  -d '{"ispb": "12345678", "usuario": "USUARIO_SPI", "senha": "SENHA_SPI"}'

Retorno:

json
Copiar código
{
  "hash_sessao": "abcd1234efgh5678",
  "status": "RetornoJSON:0"
}
🔹 Enviar PIX
Rota: POST /api/enviar-pix

Exemplo:

bash
Copiar código
curl -X POST http://127.0.0.1:8000/api/enviar-pix \
  -H "Content-Type: application/json" \
  -d '{
        "chave_destino": "email@dominio.com",
        "valor": 10.50,
        "mensagem": "Pagamento de teste",
        "nome_pagador": "João da Silva",
        "cpf_cnpj_pagador": "12345678900",
        "ispb_pagador": "99999999",
        "agencia_pagador": "0001",
        "conta_pagador": "12345",
        "tipo_conta_pagador": "CACC"
      }'
Retorno:

json
Copiar código
{
  "id_transacao": "E9999999920251030123456",
  "status": "RetornoJSON:0"
}
🔹 Consultar Chaves DICT
Rota: GET /api/dict/consultar-todas

Exemplo:

bash
Copiar código
curl -X GET http://127.0.0.1:8000/api/dict/consultar-todas?TaxIdNumber=12345678900
Retorno:

json
Copiar código

{
  "DictConsultarTodasChavesResponse": {
    "Retorno": 0,
    "TotalElements": 1,
    "Chaves": [
      {
        "Key": "email@dominio.com",
        "KeyType": "EMAIL",
        "Branch": "0001",
        "AccountNumber": "12345",
        "AccountType": "CACC",
        "TaxIdNumber": "12345678900"
      }
    ]
  }
}

🧰 Tecnologias Utilizadas
Tecnologia	Descrição
FastAPI	Framework moderno e assíncrono
HTTPX	Cliente HTTP com suporte a mTLS
Cryptography	Manipulação de certificados PFX
SignXML	Assinatura digital XMLDSig
LXML	Criação e manipulação de XML ISO 20022
Pydantic	Modelagem e validação de dados
Dotenv	Leitura de variáveis de ambiente

🧩 Fluxo de Operações
1️⃣ /api/conectar → autentica e retorna hash_sessao
2️⃣ /api/enviar-pix → monta, assina e envia XML pacs.008
3️⃣ /api/dict/consultar-todas → retorna chaves PIX associadas

🛠️ Futuras Melhorias
Cache de sessão e reconexão automática

Logs estruturados com loguru

Suporte direto a certificados PEM

Novos endpoints (devoluções, liquidações, etc)

📄 Licença
Este projeto é de uso interno e segue as diretrizes do Banco Central do Brasil para comunicação com o SPI e DICT.

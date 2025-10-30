import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import tempfile
from cryptography.hazmat.primitives.serialization import pkcs12, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
from lxml import etree
from datetime import datetime
import signxml # Para assinatura XMLDSig
from signxml import XMLSigner
from cryptography.hazmat.backends import default_backend
import traceback # Para logar erros completos
from typing import Any # Para o campo Problem
import json # Para tentar parsear erros HTTP

# Carrega variáveis do arquivo .env (ex: BACEN_PFX_PASSWORD, SEU_ISPB_AQUI)
load_dotenv()

# --- Imports e Definições SOAP ---
from lxml.builder import ElementMaker
SOAP_ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
CMSPB_NS = "http://www.cmsw.com/cmspb/" # Namespace do WSDL
# Adiciona xsi e xsd para os atributos de tipo
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
XSD_NS = "http://www.w3.org/2001/XMLSchema"
NSMAP_SOAP = {"soapenv": SOAP_ENV_NS, "cmspb": CMSPB_NS, "xsi": XSI_NS, "xsd": XSD_NS}
# --- Construtores de Elementos XML SOAP (atualizados com xsi/xsd) ---
E = ElementMaker(namespace=CMSPB_NS, nsmap={"n": CMSPB_NS, "xsi": XSI_NS, "xsd": XSD_NS})
SOAP_E = ElementMaker(namespace=SOAP_ENV_NS, nsmap=NSMAP_SOAP)
# --- Fim das definições SOAP ---

# --- Modelos de Dados Pydantic ---
class OrdemPix(BaseModel):
    # Dados da Transação
    chave_destino: str
    valor: float
    mensagem: str
    # Dados do Pagador
    nome_pagador: str
    cpf_cnpj_pagador: str # Apenas números
    ispb_pagador: str    # Seu ISPB (8 dígitos)
    agencia_pagador: str # Agência sem dígito
    conta_pagador: str   # Conta sem dígito
    tipo_conta_pagador: str # "CACC" ou "SVGS"

class RespostaPix(BaseModel):
    id_transacao: str # Usaremos o NuOP aqui
    status: str

class ConectarCredenciais(BaseModel):
    ispb: str
    usuario: str
    senha: str

class ConectarResposta(BaseModel):
    hash_sessao: str
    status: str

# --- Modelos para DictConsultar ---
class DictConsultarBody(BaseModel):
    Key: str
    piPayerId: str
    EndToEndId: str | None = None

class AccountResponseModel(BaseModel):
    Participant: str | None = None
    Branch: str | None = None
    AccountNumber: str | None = None
    AccountType: str | None = None
    OpeningDate: str | None = None

class OwnerEntryModel(BaseModel):
    Type: str | None = None
    TaxIdNumber: str | None = None
    Name: str | None = None
    TradeName: str | None = None

class DictConsultarResponseData(BaseModel):
    Retorno: int | str
    Problem: Any | None = None
    Key: str | None = None
    KeyType: str | None = None
    Account: AccountResponseModel | None = None
    Owner: OwnerEntryModel | None = None
    CreationDate: str | None = None
    KeyOwnershipDate: str | None = None

class DictConsultarResponseModel(BaseModel):
    DictConsultarResponse: DictConsultarResponseData | None = None
    detail: str | None = None

# --- Modelos para DictConsultarTodasChaves ---
class DictConsultarTodasChavesBody(BaseModel):
    KeyType: str | None = None
    Branch: str | None = None
    AccountNumber: str | None = None
    AccountType: str | None = None
    TaxIdNumber: str | None = None
    Limit: int | None = None

class ChaveAtributeModel(BaseModel):
    Key: str | None = None
    KeyType: str | None = None
    Branch: str | None = None
    AccountNumber: str | None = None
    AccountType: str | None = None
    TaxIdNumber: str | None = None
    Data_Inclusao: str | None = None
    Data_Alteracao: str | None = None

class DictConsultarTodasChavesResponseData(BaseModel):
    Retorno: int | str
    Problem: Any | None = None
    Ispb: str | None = None
    TotalElements: int | None = None
    Chaves: list[ChaveAtributeModel] | None = None

class DictConsultarTodasChavesResponseModel(BaseModel):
    DictConsultarTodasChavesResponse: DictConsultarTodasChavesResponseData | None = None
    detail: str | None = None

# --- Variável Global para guardar o Hash ---
GLOBAL_SESSION_HASH = None

# --- CONFIGURAÇÃO DE CERTIFICADOS ---
PFX_PASSWORD = os.environ.get("BACEN_PFX_PASSWORD")
PFX_FILE_PATH = r"C:\Users\ViniciusPaula\Legado\diretorio\seu.pfx" # Use o PFX correto de HML
VERIFY_CERTS_PATH = r"C:\caminho\para\o\pem_de_hml.pem" # <- Placeholder 

if not PFX_PASSWORD:
    raise ValueError("A variável de ambiente 'BACEN_PFX_PASSWORD' não foi definida.")

# --- CARREGANDO OS DADOS DO PFX PARA ASSINATURA ---
print(f"Carregando PFX de: {PFX_FILE_PATH} para assinatura...")
try:
    with open(PFX_FILE_PATH, "rb") as f: pfx_data = f.read()
    GLOBAL_PRIVATE_KEY, GLOBAL_CERT, GLOBAL_ADDITIONAL_CERTS = pkcs12.load_key_and_certificates(pfx_data, PFX_PASSWORD.encode('utf-8'), default_backend())
    print("Chave privada e certificado carregados em memória para assinatura.")
except FileNotFoundError: raise SystemExit(f"Arquivo PFX não encontrado: {PFX_FILE_PATH}")
except Exception as e: raise SystemExit(f"Erro ao carregar PFX: {e}")

# --- FUNÇÃO DE EXTRAÇÃO (Para mTLS) ---
def extract_pfx_to_temp_files(pfx_path: str, pfx_password: str) -> tuple[str, str]:
    print(f"Extraindo PFX para arquivos temporários (mTLS)...")
    try:
        private_key = GLOBAL_PRIVATE_KEY; certificate = GLOBAL_CERT; additional_certificates = GLOBAL_ADDITIONAL_CERTS
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key.pem", mode="wb") as key_file:
            key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
            key_file.write(key_pem); key_file_path = key_file.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cert.pem", mode="wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            for cert in additional_certificates: cert_file.write(b"\n"); cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
            cert_file_path = cert_file.name
        return (cert_file_path, key_file_path)
    except Exception as e: print(f"Erro ao processar o arquivo PFX para tempfiles: {e}"); raise

# --- INICIALIZAÇÃO DO CLIENTE HTTPX E APP ---
try:
    (CERT_FILE_PATH, KEY_FILE_PATH) = extract_pfx_to_temp_files(PFX_FILE_PATH, PFX_PASSWORD)
    print(f"Chave privada (mTLS) extraída para: {KEY_FILE_PATH}")
    print(f"Certificado(s) (mTLS) extraído para: {CERT_FILE_PATH}")
except Exception as e: raise SystemExit(f"Falha ao iniciar: {e}")

client_mtls = httpx.AsyncClient(cert=(CERT_FILE_PATH, KEY_FILE_PATH), verify=False) # <- Lembre de corrigir verify
app = FastAPI()
URL_SPI_BASE = "sua-url" # <-- Baseado no log de sucesso

# --- ENDPOINT: /CONECTAR (JSON) ---
@app.post("/api/conectar", response_model=ConectarResposta)
async def conectar_spi(creds: ConectarCredenciais):
    global GLOBAL_SESSION_HASH
    print(f"Tentando conectar com ISPB: {creds.ispb}, Usuario: {creds.usuario}")
    request_body = {"ConectarRequest": {"ISPB": creds.ispb, "Usuario": creds.usuario, "Senha": creds.senha}}
    headers = {'Content-Type': 'application/json'}
    try:
        URL_OPERACAO_CONECTAR = URL_SPI_BASE + "api/Conectar"
        print(f"Enviando JSON (Conectar) para {URL_OPERACAO_CONECTAR}...")
        response = await client_mtls.post(URL_OPERACAO_CONECTAR, json=request_body, headers=headers, timeout=10.0)
        response.raise_for_status()
        print(f"Resposta JSON (Conectar) (Status): {response.status_code}"); print(f"Resposta JSON (Conectar) (Body): {response.text}")
        try:
            response_data = response.json(); conectar_response = response_data.get("ConectarResponse")
            if conectar_response:
                retorno_code = conectar_response.get("Retorno"); hash_sessao = conectar_response.get("Hash"); problema = conectar_response.get("Problem")
                status_real = f"RetornoJSON:{retorno_code}";
                if problema: status_real += f" | Problema: {problema}"
                
                
                retorno_int = -1
                try:
                    retorno_int = int(retorno_code)
                except (ValueError, TypeError):
                    pass
                

                if hash_sessao and retorno_int == 0:
                    GLOBAL_SESSION_HASH = hash_sessao; print(f"Conexao BEM-SUCEDIDA! Hash: {GLOBAL_SESSION_HASH}")
                    return ConectarResposta(hash_sessao=GLOBAL_SESSION_HASH, status=status_real)
                else: print(f"Falha na conexao: {status_real}"); raise HTTPException(status_code=401, detail=f"Falha ao conectar: {status_real}")
            else: raise HTTPException(status_code=502, detail="Resposta JSON (Conectar) inválida: 'ConectarResponse' não encontrada")
        except ValueError: raise HTTPException(status_code=502, detail="Resposta (Conectar) não é JSON válido")
    except httpx.HTTPStatusError as e: raise HTTPException(status_code=e.response.status_code, detail=f"Erro da API (Conectar): {e.response.text}")
    except httpx.RequestError as e: raise HTTPException(status_code=504, detail=f"Nao foi possivel conectar ao SPI (Conectar): {e}")
    except Exception as e: traceback.print_exc(); raise HTTPException(status_code=500, detail=f"Erro interno no servidor (Conectar): {e}")

# --- FUNÇÃO AUXILIAR PARA CONSULTA DICT ---
async def _consultar_dict_interno(key: str, payer_id: str, end_to_end_id: str | None) -> DictConsultarResponseData:
    if not GLOBAL_SESSION_HASH: raise HTTPException(status_code=401, detail="Hash de sessão DICT não encontrado.")
    print(f"Consulta DICT interna para Chave: {key} | Pagador: {payer_id}")
    request_body = {"DictConsultarRequest": {"Hash": GLOBAL_SESSION_HASH,"Key": key,"piPayerId": payer_id,"EndToEndId": end_to_end_id if end_to_end_id else ""}}
    headers = {'Content-Type': 'application/json'}
    URL_OPERACAO_DICT = URL_SPI_BASE + "api/DictConsultar"
    try:
        response = await client_mtls.post(URL_OPERACAO_DICT, json=request_body, headers=headers, timeout=10.0)
        if response.status_code >= 500: response.raise_for_status()
        response_data = response.json()
        dict_response_payload = response_data.get("DictConsultarResponse")
        if dict_response_payload:
            validated_data = DictConsultarResponseData.model_validate(dict_response_payload)
            
            
            retorno_int = -1
            try:
                retorno_int = int(validated_data.Retorno)
            except (ValueError, TypeError):
                pass
            

            if retorno_int != 0 or validated_data.Problem:
                 print(f"Erro retornado pela API DICT: {validated_data.Problem or validated_data.Retorno}")
                 raise HTTPException(status_code=400, detail=response_data) # Repassa o JSON de erro completo
            return validated_data # Sucesso
        else: raise HTTPException(status_code=502, detail="Resposta DICT inválida: 'DictConsultarResponse' não encontrado")
    except ValueError: raise HTTPException(status_code=502, detail=f"Resposta DICT não é JSON válido: {response.text if 'response' in locals() else 'N/A'}")
    except httpx.HTTPStatusError as e: raise HTTPException(status_code=e.response.status_code, detail=f"Erro da API DICT (HTTP Status): {e.response.text}")
    except httpx.RequestError as e: raise HTTPException(status_code=504, detail=f"Nao foi possivel conectar ao DICT: {str(e)}")
    except Exception as e: traceback.print_exc(); raise HTTPException(status_code=500, detail=f"Erro interno na consulta DICT: {e}")

# --- ENDPOINT ENVIAR PIX (JSON com Consulta DICT Integrada e Pagador Dinâmico) ---
@app.post("/api/enviar-pix", response_model=RespostaPix)
async def enviar_pix(ordem: OrdemPix):
    if not GLOBAL_SESSION_HASH: raise HTTPException(status_code=401, detail="Não conectado. Chame /api/conectar primeiro.")
    print(f"Recebida ordem de {ordem.nome_pagador} para: {ordem.chave_destino} | Valor: {ordem.valor}")
    # --- CONSULTAR DICT ---
    print("Iniciando consulta DICT para obter dados do recebedor...")
    try:
        cpf_cnpj_para_consulta = ordem.cpf_cnpj_pagador
        chave_para_consulta = ordem.chave_destino
        print(f"Consulta DICT interna para Chave: {chave_para_consulta} | Pagador: {cpf_cnpj_para_consulta}")
        dados_recebedor_dict = await _consultar_dict_interno(key=chave_para_consulta, payer_id=cpf_cnpj_para_consulta, end_to_end_id=None)
        print("Consulta DICT bem-sucedida.")
        if not (dados_recebedor_dict.Account and dados_recebedor_dict.Owner and dados_recebedor_dict.Account.Participant):
             raise HTTPException(status_code=404, detail="Dados essenciais do recebedor não encontrados na resposta DICT.")
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=f"Falha ao consultar DICT antes de enviar: {e.detail}")
    except Exception as e:
        traceback.print_exc(); raise HTTPException(status_code=500, detail=f"Erro inesperado durante consulta DICT: {e}")
    # --- FIM CONSULTA DICT ---

    # ETAPA 1: Montar o XML (pacs.008)
    print("Montando XML pacs.008...");
    NS_PACS = "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08"; NS_MAP_PACS = {None: NS_PACS}
    xml_doc = etree.Element("Document", Id="doc-assinado", nsmap=NS_MAP_PACS); main_msg = etree.SubElement(xml_doc, "FIToFICstmrCdtTrf")
    grp_hdr = etree.SubElement(main_msg, "GrpHdr"); msg_id = etree.SubElement(grp_hdr, "MsgId")
    seu_ispb_msg = ordem.ispb_pagador
    msg_id.text = f"M{seu_ispb_msg}{datetime.now().strftime('%Y%m%d%H%M%S')}{int(datetime.now().timestamp()*1000)%1000000:06d}"
    cre_dt_tm = etree.SubElement(grp_hdr, "CreDtTm"); cre_dt_tm.text = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    nb_of_txs = etree.SubElement(grp_hdr, "NbOfTxs"); nb_of_txs.text = "1"
    sttlm_inf = etree.SubElement(grp_hdr, "SttlmInf"); sttlm_mtd = etree.SubElement(sttlm_inf, "SttlmMtd"); sttlm_mtd.text = "CLRG"
    pmt_tp_inf = etree.SubElement(grp_hdr, "PmtTpInf"); instr_prty = etree.SubElement(pmt_tp_inf, "InstrPrty"); instr_prty.text = "HIGH"
    svc_lvl = etree.SubElement(pmt_tp_inf, "SvcLvl"); prtry_svc = etree.SubElement(svc_lvl, "Prtry"); prtry_svc.text = "PAGPRI"
    cdt_trf = etree.SubElement(main_msg, "CdtTrfTxInf"); pmt_id = etree.SubElement(cdt_trf, "PmtId"); end_to_end_id = etree.SubElement(pmt_id, "EndToEndId")
    sequencial_diario = f"{int(datetime.now().timestamp()*1000000):011d}"[-11:]
    end_to_end_id.text = f"E{seu_ispb_msg}{datetime.now().strftime('%Y%m%d')}{sequencial_diario}"
    intr_bk_sttlm_amt = etree.SubElement(cdt_trf, "IntrBkSttlmAmt", Ccy="BRL"); intr_bk_sttlm_amt.text = f"{ordem.valor:.2f}"
    accptnc_dt_tm = etree.SubElement(cdt_trf, "AccptncDtTm"); accptnc_dt_tm.text = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    chrg_br = etree.SubElement(cdt_trf, "ChrgBr"); chrg_br.text = "SLEV" 
    mndt_rltd_inf = etree.SubElement(cdt_trf, "MndtRltdInf"); tp_mndt = etree.SubElement(mndt_rltd_inf, "Tp"); lcl_instrm_mndt = etree.SubElement(tp_mndt, "LclInstrm"); prtry_mndt = etree.SubElement(lcl_instrm_mndt, "Prtry"); prtry_mndt.text = "DICT"
    dbtr = etree.SubElement(cdt_trf, "Dbtr"); etree.SubElement(dbtr, "Nm").text = ordem.nome_pagador
    dbtr_id = etree.SubElement(dbtr, "Id"); dbtr_prvt_id = etree.SubElement(dbtr_id, "PrvtId"); dbtr_othr_id = etree.SubElement(dbtr_prvt_id, "Othr"); etree.SubElement(dbtr_othr_id, "Id").text = ordem.cpf_cnpj_pagador
    dbtr_acct = etree.SubElement(cdt_trf, "DbtrAcct"); dbtr_acct_id = etree.SubElement(dbtr_acct, "Id"); dbtr_acct_othr = etree.SubElement(dbtr_acct_id, "Othr"); etree.SubElement(dbtr_acct_othr, "Id").text = ordem.conta_pagador; etree.SubElement(dbtr_acct_othr, "Issr").text = ordem.agencia_pagador
    dbtr_acct_tp = etree.SubElement(dbtr_acct, "Tp"); etree.SubElement(dbtr_acct_tp, "Cd").text = ordem.tipo_conta_pagador
    dbtr_agt = etree.SubElement(cdt_trf, "DbtrAgt"); dbtr_agt_fin_instn_id = etree.SubElement(dbtr_agt, "FinInstnId"); dbtr_agt_clr_sys_mmb_id = etree.SubElement(dbtr_agt_fin_instn_id, "ClrSysMmbId"); etree.SubElement(dbtr_agt_clr_sys_mmb_id, "MmbId").text = ordem.ispb_pagador
    ispb_recebedor = dados_recebedor_dict.Account.Participant; nome_recebedor = dados_recebedor_dict.Owner.Name; cpf_cnpj_recebedor = dados_recebedor_dict.Owner.TaxIdNumber
    conta_recebedor = dados_recebedor_dict.Account.AccountNumber; agencia_recebedor = dados_recebedor_dict.Account.Branch; tipo_conta_recebedor = dados_recebedor_dict.Account.AccountType
    cdtr_agt = etree.SubElement(cdt_trf, "CdtrAgt"); cdtr_agt_fin_instn_id = etree.SubElement(cdtr_agt, "FinInstnId"); cdtr_agt_clr_sys_mmb_id = etree.SubElement(cdtr_agt_fin_instn_id, "ClrSysMmbId"); etree.SubElement(cdtr_agt_clr_sys_mmb_id, "MmbId").text = ispb_recebedor
    cdtr = etree.SubElement(cdt_trf, "Cdtr"); etree.SubElement(cdtr, "Nm").text = nome_recebedor
    cdtr_id = etree.SubElement(cdt_trf, "Id"); cdtr_prvt_id = etree.SubElement(cdtr_id, "PrvtId"); cdtr_othr_id = etree.SubElement(cdtr_prvt_id, "Othr"); etree.SubElement(cdtr_othr_id, "Id").text = cpf_cnpj_recebedor
    cdtr_acct = etree.SubElement(cdt_trf, "CdtrAcct"); cdtr_acct_id = etree.SubElement(cdtr_acct, "Id"); cdtr_acct_othr = etree.SubElement(cdtr_acct_id, "Othr"); etree.SubElement(cdtr_acct_othr, "Id").text = conta_recebedor; etree.SubElement(cdtr_acct_othr, "Issr").text = agencia_recebedor
    cdtr_acct_tp = etree.SubElement(cdtr_acct, "Tp"); etree.SubElement(cdtr_acct_tp, "Cd").text = tipo_conta_recebedor
    cdtr_acct_prxy = etree.SubElement(cdtr_acct, "Prxy"); etree.SubElement(cdtr_acct_prxy, "Id").text = ordem.chave_destino
    purp = etree.SubElement(cdt_trf, "Purp"); etree.SubElement(purp, "Cd").text = "IPAY"
    rmt_inf = etree.SubElement(cdt_trf, "RmtInf"); etree.SubElement(rmt_inf, "Ustrd").text = ordem.mensagem[:140]
    try: dados_xml_para_assinar = etree.tostring(xml_doc, method="c14n", exclusive=True); dados_root = etree.fromstring(dados_xml_para_assinar)
    except Exception as e: raise HTTPException(status_code=500, detail=f"Erro ao preparar XML: {e}")
    
    # ETAPA 2: Assinar o XML (XMLDSig)
    print("Iniciando assinatura digital do XML..."); signer = XMLSigner(method=signxml.methods.enveloped, c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    cert_pem = GLOBAL_CERT.public_bytes(serialization.Encoding.PEM); chain_pem = [cert.public_bytes(serialization.Encoding.PEM) for cert in GLOBAL_ADDITIONAL_CERTS]; full_chain_pems = [cert_pem] + chain_pem
    try:
        xml_assinado_elemento = signer.sign(dados_root, key=GLOBAL_PRIVATE_KEY, cert=full_chain_pems, reference_uri="#doc-assinado")
        print("--- XML ASSINADO COMPLETO (pacs.008) ---")
        mensagem_assinada_xml_bytes = etree.tostring(xml_assinado_elemento, encoding="UTF-8", xml_declaration=True, pretty_print=True)
        print(mensagem_assinada_xml_bytes.decode('utf-8'))
        print("------------------------------------------")
        xml_assinado_str = etree.tostring(xml_assinado_elemento, encoding='unicode')
    except Exception as e: traceback.print_exc(); raise HTTPException(status_code=500, detail=f"Erro ao assinar XML: {e}")
    
    # ETAPA 3: Chamar a API do SPI (JSON)
    print("Preparando corpo JSON para EnviarMensagem..."); valor_ispb_destino = ispb_recebedor
    request_body_enviar = {"EnviarMensagemRequest": {"Hash": GLOBAL_SESSION_HASH,"MsgXML": xml_assinado_str,"IdentdDestinatario": valor_ispb_destino}}
    headers = {'Content-Type': 'application/json'}
    try:
        URL_OPERACAO_ENVIAR = URL_SPI_BASE + "api/EnviarMensagem"
        print(f"Enviando JSON (EnviarMensagem) para {URL_OPERACAO_ENVIAR}..."); print(f"Request Body Enviar (sem MsgXML): {{'EnviarMensagemRequest': {{'Hash': '{GLOBAL_SESSION_HASH}', 'IdentdDestinatario': '{valor_ispb_destino}'}}}}")
        response = await client_mtls.post(URL_OPERACAO_ENVIAR, json=request_body_enviar, headers=headers, timeout=10.0)
        response.raise_for_status()
        print(f"Resposta JSON (EnviarMensagem) (Status): {response.status_code}"); print(f"Resposta JSON (EnviarMensagem) (Body): {response.text}")
        try:
            response_data = response.json(); enviar_response = response_data.get("EnviarMensagemResponse")
            if enviar_response:
                retorno_code = enviar_response.get("Retorno"); nuop = enviar_response.get("NuOP"); problema = enviar_response.get("Problem")
                status_real = f"RetornoJSON:{retorno_code}";
                if problema: status_real += f" | Problema: {problema}"
                
                
                retorno_int = -1
                try:
                    retorno_int = int(retorno_code)
                except (ValueError, TypeError):
                    pass
                
                return RespostaPix(id_transacao=nuop if nuop else "NUOP_NAO_ENCONTRADO", status=status_real)
            else: raise HTTPException(status_code=502, detail="Resposta JSON (EnviarMensagem) inválida: 'EnviarMensagemResponse' não encontrada")
        except ValueError: raise HTTPException(status_code=502, detail="Resposta (EnviarMensagem) não é JSON válido")
    except httpx.HTTPStatusError as e: raise HTTPException(status_code=e.response.status_code, detail=f"Erro da API (EnviarMensagem): {e.response.text}")
    except httpx.RequestError as e: raise HTTPException(status_code=504, detail=f"Nao foi possivel conectar ao SPI (EnviarMensagem): {e}")
    except Exception as e: traceback.print_exc(); raise HTTPException(status_code=500, detail=f"Erro interno no servidor (EnviarMensagem): {e}")


# --- ENDPOINT: /DICT/CONSULTAR-TODAS (JSON) ---
@app.post("/api/dict/consultar-todas", response_model=DictConsultarTodasChavesResponseModel)
async def dict_consultar_todas(filtros: DictConsultarTodasChavesBody | None = None):
    if not GLOBAL_SESSION_HASH: raise HTTPException(status_code=401, detail="Não conectado. Chame /api/conectar primeiro.")
    print(f"Consultando Todas as Chaves DICT com filtros: {filtros}")
    request_data = {"Hash": GLOBAL_SESSION_HASH}
    if filtros:
        for field, value in filtros.model_dump(exclude_none=True).items():
             if value is not None: request_data[field] = value
    request_body = {"DictConsultarTodasChavesRequest": request_data}
    headers = {'Content-Type': 'application/json'}
    try:
        URL_OPERACAO_DICT_TODAS = URL_SPI_BASE + "api/DictConsultarTodasChaves"
        print(f"Enviando JSON (DictConsultarTodasChaves) para {URL_OPERACAO_DICT_TODAS}..."); print(f"Request Body: {request_body}")
        response = await client_mtls.post(URL_OPERACAO_DICT_TODAS, json=request_body, headers=headers, timeout=30.0)
        response.raise_for_status()
        print(f"Resposta JSON (DictConsultarTodasChaves) (Status): {response.status_code}"); print(f"Resposta JSON (DictConsultarTodasChaves) (Body): {response.text}")
        try: response_data = response.json(); return response_data
        except ValueError: return DictConsultarTodasChavesResponseModel(detail=f"Resposta (DictConsultarTodasChaves) não é JSON válido: {response.text}")
    except httpx.HTTPStatusError as e:
        print(f"Erro HTTP da API (DictConsultarTodasChaves): {e.response.status_code}"); print(f"Corpo da Resposta: {e.response.text}")
        try: error_data = e.response.json(); return error_data
        except ValueError: return DictConsultarTodasChavesResponseModel(detail=f"Erro da API (DictConsultarTodasChaves): Status {e.response.status_code} - {e.response.text}")
    except httpx.RequestError as e:
        error_details = str(e); print(f"Erro de conexão (DictConsultarTodasChaves): {error_details}")
        raise HTTPException(status_code=504, detail=f"Nao foi possivel conectar ao SPI (DictConsultarTodasChaves): {error_details}")
    except Exception as e:
        print(f"Erro interno inesperado (DictConsultarTodasChaves): {e}"); traceback.print_exc()
        return DictConsultarTodasChavesResponseModel(detail=f"Erro interno no servidor (DictConsultarTodasChaves): {e}")

# --- ENDPOINT: /DICT/CONSULTAR (JSON) ---
@app.post("/api/dict/consultar", response_model=DictConsultarResponseModel)
async def dict_consultar(consulta: DictConsultarBody):
    try:
        dados_consulta = await _consultar_dict_interno(key=consulta.Key, payer_id=consulta.piPayerId, end_to_end_id=consulta.EndToEndId)
        return DictConsultarResponseModel(DictConsultarResponse=dados_consulta)
    except HTTPException as e:
        detail_content = e.detail
        try:
             if isinstance(detail_content, dict): return detail_content # Se já for dict (erro DICT)
             detail_json = json.loads(str(detail_content)); return detail_json # Se for string JSON (erro DICT)
        except (json.JSONDecodeError, TypeError): pass # Se não for JSON
        return DictConsultarResponseModel(detail=str(detail_content)) # Retorna erro da nossa API
    except Exception as e:
         traceback.print_exc()
         return DictConsultarResponseModel(detail=f"Erro inesperado no servidor ao consultar DICT: {e}")

# --- Ponto de Entrada para Uvicorn (Opcional) ---
# import uvicorn
# if __name__ == "__main__":
#     uvicorn.run(app, host="127.0.0.1", port=8000)


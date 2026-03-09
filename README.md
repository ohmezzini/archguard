# ArchGuard

ArchGuard é uma plataforma experimental criada para ajudar equipes de segurança a avaliarem a postura de segurança de microserviços de forma estruturada, utilizando controles de segurança, contexto de ataques reais e entrevistas guiadas.

A ideia do projeto é substituir análises feitas em **planilhas ou documentos estáticos** por uma plataforma simples e interativa.

---

# Problema

Em muitas organizações, revisões de arquitetura e análises de risco ainda são realizadas em:

- planilhas
- documentos Word
- checklists manuais

Isso gera problemas como:

- falta de padronização
- pouca rastreabilidade
- dificuldade de correlacionar riscos com ataques reais
- pouca visibilidade da postura de segurança entre sistemas

---

# Objetivo do ArchGuard

O ArchGuard foi criado como um experimento para mostrar como análises de arquitetura de segurança podem evoluir para uma plataforma simples.

A plataforma permite:

- registrar microserviços
- avaliar controles de segurança da arquitetura
- utilizar contexto do MITRE ATT&CK
- executar entrevistas guiadas
- gerar score de postura de segurança
- visualizar riscos através de um modelo de farol

---

# Funcionalidades

## Inventário de microserviços

Cadastro de serviços com informações como:

- nome do serviço
- time responsável
- domínio
- ambiente (prod / hml / dev)
- plataforma (EKS / ECS)
- nível de exposição
- classificação de dados

---

## Blueprint de arquitetura

Cada serviço possui um blueprint com controles como:

- Identity & Access
- Network Exposure
- Data Protection
- Observability & Incident Response
- Supply Chain Security

---

## Avaliação de segurança

A plataforma gera:

- score de segurança por domínio
- score geral
- farol de risco

Classificação utilizada:
- Baixo
- Médio
- Alto
- Desconhecido

Tecnologias utilizadas:
- FastAPI
- PostgreSQL
- Docker
- Chart.js
- OpenAI API

---
# Como executar o ArchGuard
Clone o repositório e execute:

docker compose up -d --build

Depois acesse o:
http://localhost:8000


# Roadmap futuro

Possíveis evoluções:

- integração com AWS Security Hub
- integração com DefectDojo
- integração com Jira
- ingestão de findings de scanners
- análise de risco por ativo
- evolução de postura ao longo do tempo

---

# Autor
Fernando Norberto
LinkedIn: https://www.linkedin.com/in/fernando-norberto-39842b22/
Projeto desenvolvido com apoio da OpenAI.

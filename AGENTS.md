# Inicialização do Agente (Contexto da Aplicação)

## 📌 Visão Geral do Projeto (Git Context Controller - GCC-MCP)

O **GCC-MCP** é um servidor MCP (Model Context Protocol) e CLI desenvolvido em Python (>=3.10). Ele atua como um sistema estruturado de **memória orientada a contexto** para agentes de IA (como eu), utilizando operações inspiradas no Git.
Isso permite manter checkpoints, histórico de decisões, recuperar preferências de código e garantir a continuidade entre múltiplas sessões do agente.

A aplicação guarda seus estados na pasta `.GCC/` (com `main.md`, `commit.md` e `log.md`) e suporta integrações locais (via `stdio`) e remotas (via `streamable-http`).

## 🎯 Objetivo Atual (Deploy na VPS com Traefik)

De acordo com o `TASKS.md`, o objetivo principal no momento é preparar o ambiente e realizar o **deploy do servidor GCC-MCP em produção** utilizando **Docker** e **Traefik** como proxy reverso seguro.

### ✨ Checklist de Execução

Abaixo estão os passos estipulados para a missão:

**1. Preparação de Segurança e Chaves**

- [ ] Criar diretório `secrets` (`mkdir -p secrets`).
- [ ] Gerar uma chave hexadecimal de 64 caracteres para o log de auditoria: `openssl rand -hex 32 > secrets/audit-signing.key`.
- [ ] Ajustar permissões para `chmod 600 secrets/audit-signing.key`.

**2. Configuração do Ambiente (`.env`)**

- [ ] Criar o `.env` a partir do `.env.example`.
- [ ] Definir o token em `GCC_MCP_AUTH_TOKEN`.
- [ ] Habilitar `GCC_MCP_ALLOW_PUBLIC_HTTP=true` (necessário para o Traefik acessar o container na 0.0.0.0 internamente).
- [ ] Mapear diretórios de contexto do VPS usando `GCC_MCP_PATH_MAP` e `GCC_MCP_ALLOWED_ROOTS`.

**3. Integração com o Traefik (`docker-compose.prod.yml`)**

- [ ] Remover a exposição direta da porta do host (`127.0.0.1:8000:8000`).
- [ ] Adicionar as **labels do Traefik** para roteamento HTTP, definição de domínio e SSL.
- [ ] Configurar a rede externa Docker do Traefik (`networks`).

**4. Validação e Deploy**

- [ ] Rodar o script de pré-requisitos: `./scripts/check-container-prereqs.sh`.
- [ ] Subir o contêiner: `docker compose -f docker-compose.prod.yml up -d`.

## 🛠️ Tecnologias e Ferramentas Empregadas

- **Linguagem**: Python >= 3.10
- **Ferramenta de empacotamento**: `uv` e `pyproject.toml`
- **Infraestrutura**: Docker Compose (múltiplos estágios, testes, prod)
- **Segurança**: Log de auditoria assinado em JSONL, modo de autenticação via Token, perfis de segurança estritos.

---

> **Nota para o Agente**: Ao executar as tarefas estipuladas, atualizar este documento ou os arquivos correspondentes do projeto. Já compreendo perfeitamente o contexto da aplicação e da tarefa estabelecida no `TASKS.md`! Pode solicitar os próximos passos.

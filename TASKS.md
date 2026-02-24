Objetivo: Fazer o deploy do servidor Git-Context-Controller (GCC-MCP) em uma VPS usando Docker e integrá-lo ao Traefik como proxy reverso seguro.
Passo 1: Preparação de Segurança e Chaves
1. Crie um diretório para os segredos: mkdir -p secrets.
2. Gere a chave de assinatura de auditoria exigida pelo perfil estrito: openssl rand -hex 32 > secrets/audit-signing.key.
3. Ajuste as permissões do arquivo da chave para segurança: chmod 600 secrets/audit-signing.key.
Passo 2: Configuração do Ambiente (.env)
1. Copie o arquivo de exemplo: cp .env.example .env.
2. Edite o .env e defina um token forte na variável GCC_MCP_AUTH_TOKEN.
3. Certifique-se de que a variável GCC_MCP_ALLOW_PUBLIC_HTTP=true esteja ativada, pois o contêiner precisará escutar em 0.0.0.0 internamente para receber o tráfego do Traefik.
4. Configure as variáveis GCC_MCP_PATH_MAP e GCC_MCP_ALLOWED_ROOTS para mapear os diretórios da VPS para dentro do contêiner, permitindo que a IA acesse as pastas corretas dos projetos.
Passo 3: Adaptação para o Traefik (docker-compose.prod.yml)
1. Abra o arquivo docker-compose.prod.yml.
2. Remova a exposição direta de portas para o host (ports: - "127.0.0.1:8000:8000") para evitar conflitos ou exposição acidental.
3. Adicione as labels do Traefik ao serviço para configurar o roteamento HTTP, o domínio de acesso e o certificado SSL/TLS.
4. Conecte o serviço à rede Docker externa que o Traefik utiliza.
Passo 4: Validação e Deploy
1. Execute o script de verificação do repositório para garantir que tudo está correto: ./scripts/check-container-prereqs.sh.
2. Suba o contêiner usando o arquivo de produção: docker compose -f docker-compose.prod.yml up -d.

--------------------------------------------------------------------------------
Isso dará à sua IA o contexto perfeito e o passo a passo exato validado pela documentação.
# SA-MP Host Panel v0.3

Inclui:
- cadastro/login
- servidores por usuário
- iniciar/reiniciar/parar
- IP:porta
- console/logs em atualização automática
- listagem de arquivos
- endpoint administrativo protegido por ADMIN_EMAIL
- persistência local

## Rodar
Node.js 18+:
npm install
npm start

Para definir administrador:
Linux/macOS: `ADMIN_EMAIL=seu@email.com npm start`
Windows PowerShell: `$env:ADMIN_EMAIL="seu@email.com"; npm start`

## Servidor SA-MP
Coloque `samp-server` (Linux) ou `samp-server.exe` (Windows) em `servers/<id>/`.

## VPS
Em produção, use VPS com IP público, firewall liberando a porta UDP/TCP necessária ao seu servidor, HTTPS/reverse proxy, isolamento por processo/container, limites de CPU/RAM, backups e banco de dados adequado.

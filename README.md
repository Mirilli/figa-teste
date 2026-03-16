# 🌾 GranoVita – Loja Online de Granola

Stack full-stack com foco em **segurança**, **integridade de dados** e **integração com Mercado Pago**.

---

## 🏗️ Arquitetura

```
granovita/
├── server.js              # Express – ponto de entrada
├── .env.example           # Variáveis de ambiente (copiar para .env)
├── src/
│   ├── database.js        # SQLite (better-sqlite3) + schema + seed
│   ├── middleware/
│   │   ├── auth.js        # JWT (access + refresh tokens)
│   │   └── security.js    # Rate limiting, HMAC, webhook verify, audit
│   └── routes/
│       ├── auth.js        # Login, register, refresh, logout
│       ├── orders.js      # Criação e consulta de pedidos
│       ├── payments.js    # Mercado Pago Checkout Pro + Webhook
│       └── admin.js       # Dashboard, pedidos, usuários, produtos
└── public/
    ├── index.html         # Loja (SPA)
    └── admin.html         # Painel administrativo
```

---

## 🚀 Setup Rápido

### 1. Pré-requisitos
- Node.js 18+
- npm ou yarn

### 2. Instalar dependências
```bash
npm install
```

### 3. Configurar variáveis de ambiente
```bash
cp .env.example .env
# Edite .env com seus valores reais
```

**Variáveis obrigatórias:**
| Variável | Descrição |
|---|---|
| `JWT_ACCESS_SECRET` | String aleatória ≥64 chars |
| `JWT_REFRESH_SECRET` | String aleatória ≥64 chars diferente |
| `MP_ACCESS_TOKEN` | Token do Mercado Pago (produção ou sandbox) |
| `MP_WEBHOOK_SECRET` | Segredo do webhook configurado no painel do MP |
| `BASE_URL` | URL pública do servidor (ex: https://seusite.com.br) |
| `ADMIN_EMAIL` | E-mail do admin inicial |
| `ADMIN_PASSWORD` | Senha forte do admin |

### 4. Gerar segredos JWT
```bash
node -e "require('crypto').randomBytes(64).toString('hex') |> console.log"
# Rode duas vezes para JWT_ACCESS_SECRET e JWT_REFRESH_SECRET
```

### 5. Iniciar
```bash
# Desenvolvimento
npm run dev

# Produção
NODE_ENV=production npm start
```

---

## 🔐 Segurança Implementada

### Autenticação
- **Bcrypt** (salt rounds=12) para senhas — nunca armazena texto puro
- **JWT de curta duração** (15min) + **Refresh Token rotativo** (7d)
- Refresh tokens **hasheados** no banco (SHA-256) — nunca em texto puro
- **Detecção de roubo**: reuso de refresh token invalida toda a sessão
- Cookies `httpOnly + Secure + SameSite=Strict` para refresh tokens
- Proteção contra **timing attacks** no login (bcrypt sempre executa)
- Proteção contra **user enumeration** (mensagens genéricas)

### Rate Limiting
- Geral: 100 req/15min por IP
- Login: 5 tentativas/15min por IP+email (brute force)
- Cadastro: 10/hora por IP

### Integridade de Pedidos
- **HMAC-SHA256** gerado na criação do pedido com: userId + items (id, qty, preço) + total
- Verificado **antes de criar a preferência** no Mercado Pago
- Verificado **novamente no webhook** antes de confirmar pagamento
- Preços sempre lidos do **banco de dados** — nunca aceitos do cliente

### Webhook (Mercado Pago)
- Verificação de **assinatura HMAC-SHA256**
- Proteção contra **replay attacks** (timestamp com janela de 5min)
- Idempotência — status não regride

### Headers & API
- **Helmet.js** — Content-Security-Policy, X-Frame-Options, etc.
- **CORS** restrito a origens explícitas
- Payload limitado a 64KB (proteção DoS)
- Dados sensíveis **nunca retornados** (password_hash, integrity_hash)

### Auditoria
- Log de todas as ações sensíveis: login, cadastro, pedidos, pagamentos, alterações de admin
- Armazenado com IP, user-agent e timestamp

---

## 💳 Configurar Mercado Pago

### 1. Obter credenciais
- Acesse: https://www.mercadopago.com.br/developers/panel
- Crie um app e copie o **Access Token** e **Public Key**

### 2. Configurar Webhook
- Em "Configurações" > "Webhooks", crie uma notificação:
  - URL: `https://seusite.com.br/api/payments/webhook`
  - Eventos: `payment`
- Copie o **secret** gerado e coloque em `MP_WEBHOOK_SECRET`

### 3. Sandbox para testes
- Use as credenciais de **teste** no `.env`
- URLs de checkout serão em `sandbox.mercadopago.com.br`

---

## 🏭 Deploy em Produção (Recomendado: Railway / Render / VPS)

### Railway (mais fácil)
```bash
npm install -g @railway/cli
railway login
railway new
railway up
# Configure as variáveis de ambiente no dashboard
```

### VPS com Nginx
```nginx
server {
    server_name seusite.com.br;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# PM2 para manter o processo
npm install -g pm2
NODE_ENV=production pm2 start server.js --name granovita
pm2 save && pm2 startup
```

---

## 📊 Painel Admin

Acesse em: `https://seusite.com.br/admin.html`

Funcionalidades:
- **Dashboard**: receita, pedidos hoje, clientes, estoque, top produtos
- **Pedidos**: lista paginada, filtros por status, atualização de status
- **Produtos & Estoque**: editar preço e estoque inline
- **Clientes**: lista com total gasto, bloquear/ativar usuários
- **Log de Auditoria**: rastreamento de todas as ações sensíveis

---

## 🔌 Ativar Rastreamento (Analytics)

### Google Tag Manager
No `public/index.html`, descomente o bloco `<!-- Google Tag Manager -->` e substitua `GTM-XXXXXXX`.

### Meta Pixel
Descomente o bloco `<!-- Meta Pixel -->` e substitua `PIXEL_ID`.

### Eventos já mapeados
- `AddToCart` — ao adicionar produto ao carrinho
- `InitiateCheckout` — ao iniciar checkout
- `Purchase` — configure no GTM via webhook de confirmação
- `Lead` — ao cadastrar e-mail na newsletter

---

## 📝 Licença
MIT

# CertiPay — MVP Micro‑SaaS de Certificados

Projeto completo para emissão de certificados de cursos do YouTube com prova, pagamento e validação pública.

## Stack
- Backend: Node.js + Express (TypeScript)
- Banco: SQLite (`better-sqlite3`) + Drizzle ORM
- Auth: JWT (cookies httpOnly)
- PDF: PDFKit
- QR Code: `qrcode`
- Pagamentos: Stripe (Checkout + Webhook)
- Frontend: EJS (SSR) + HTML/CSS moderno

## Rotas Principais
- Criador:
  - `POST /creator/register`
  - `POST /creator/login`
  - `POST /creator/course`
  - `POST /creator/questions`
  - `GET /creator/dashboard`
- Aluno:
  - `POST /student/register`
  - `POST /student/login`
  - `GET /course/:id`
  - `GET /exam/:courseId`
  - `POST /exam/:courseId`
- Pagamento:
  - `POST /payment/create`
  - `POST /payment/webhook`
- Certificado:
  - `GET /certificate/:code`

## Variáveis de Ambiente
Crie um arquivo `.env` na raiz com:

```
PORT=3000
PUBLIC_URL=http://localhost:3000
JWT_SECRET=troque-este-segredo
STRIPE_SECRET=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

## Como Rodar
```
npm install
npm run migrate
npm run seed
npm run dev
```
Acesse: `http://localhost:3000/`

### Teste de Webhook
- Use `stripe listen --forward-to localhost:3000/payment/webhook` com a CLI da Stripe.
- Configure `STRIPE_WEBHOOK_SECRET` com o valor retornado.

## Observações
- Comissão: 20% plataforma / 80% criador (calculada em `transactions`).
- PDFs gerados em `./certificados/` e servidos em `/certificados/:arquivo`.
- UI responsiva e minimalista, estilo SaaS 2025.
- Seeds: criador demo + curso demo com perguntas.

## Próximos Passos (opcional)
- Adicionar gráficos simples no dashboard do criador.
- Implementar stub de Mercado Pago.
- Adicionar testes unitários com Vitest.
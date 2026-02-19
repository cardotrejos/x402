# Architecture

## Module Layers

```
[Public API]     X402.PaymentRequired, X402.PaymentSignature, X402.PaymentResponse
                     ↓
[Middleware]      X402.Plug.PaymentGate (Plug-based HTTP gating)
                     ↓
[Facilitator]    X402.Facilitator (GenServer) → X402.Facilitator.HTTP (Req)
                     ↓
[Extensions]     PaymentIdentifier (dedup), SIWx (wallet identity)
                     ↓
[Infrastructure] X402.Wallet (address utils), X402.Telemetry (events), X402.Hooks (lifecycle)
```

## Data Flow

1. Client hits endpoint → gets 402 + `PAYMENT-REQUIRED` header
2. Client pays USDC on Base/Solana
3. Client retries with `PAYMENT-SIGNATURE` header
4. `PaymentGate` plug intercepts → calls `Facilitator.verify/2`
5. Facilitator calls external facilitator API (`/verify`)
6. On success → serves resource, triggers `Facilitator.settle/2` async
7. Hooks fire at each stage (before_verify, after_verify, after_settle)

## Extension Points
- `X402.Hooks` — inject custom logic at any lifecycle stage
- `X402.Extensions.PaymentIdentifier` — track/dedup payments via ETS
- `X402.Extensions.SIWx` — wallet-based identity (Sign-In with X)

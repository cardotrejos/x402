Mox.defmock(X402.PaymentIdentifierCacheMock, for: X402.Extensions.PaymentIdentifier.Cache)

Mox.defmock(X402.RedisCommandMock,
  for: X402.Extensions.PaymentIdentifier.RedisCache.Command
)

ExUnit.start(exclude: [:smoke, :redis])

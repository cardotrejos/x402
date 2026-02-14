defmodule X402.Facilitator.ErrorTest do
  use ExUnit.Case, async: true

  alias X402.Facilitator.Error

  test "exception/1 builds struct with defaults and custom attrs" do
    default_error = Error.exception([])

    assert default_error.type == :transport_error
    assert default_error.status == nil
    assert default_error.body == nil
    assert default_error.reason == nil
    assert default_error.retryable == false
    assert default_error.attempt == nil

    error =
      Error.exception(
        type: :http_error,
        status: 503,
        body: %{"error" => "busy"},
        reason: :server_busy,
        retryable: true,
        attempt: 3
      )

    assert error.type == :http_error
    assert error.status == 503
    assert error.body == %{"error" => "busy"}
    assert error.reason == :server_busy
    assert error.retryable == true
    assert error.attempt == 3
  end

  test "message/1 includes status, attempt, retryable, and reason when present" do
    error =
      Error.exception(
        type: :http_error,
        status: 429,
        reason: {:rate_limited, 1200},
        retryable: true,
        attempt: 2
      )

    assert Error.message(error) ==
             "facilitator request failed (type=http_error), status=429, attempt=2, retryable=true, reason={:rate_limited, 1200}"
  end

  test "message/1 omits nil status, nil attempt, and nil reason" do
    error = Error.exception(type: :invalid_option, retryable: false)

    assert Error.message(error) ==
             "facilitator request failed (type=invalid_option), retryable=false"
  end
end

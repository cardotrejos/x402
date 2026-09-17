defmodule X402.Extensions.Bazaar.MetadataTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.Bazaar.Metadata

  alias X402.Extensions.Bazaar.Metadata

  describe "valid_service_name?/1" do
    test "accepts the full printable ASCII range up to 32 characters" do
      assert Metadata.valid_service_name?(" !\"#$%&'()*+,-./09:;<=>?@AZ[\\]^_")
      assert Metadata.valid_service_name?(String.duplicate("z", 32))
    end

    test "rejects control characters, DEL, and non-binaries" do
      refute Metadata.valid_service_name?("tab\tname")
      refute Metadata.valid_service_name?("newline\n")
      refute Metadata.valid_service_name?("del\x7F")
      refute Metadata.valid_service_name?(nil)
      refute Metadata.valid_service_name?(["name"])
    end
  end

  describe "sanitize_tags/1" do
    test "keeps the first occurrence when deduplicating case-insensitively" do
      assert Metadata.sanitize_tags(["Weather", "weather", "WEATHER"]) == ["Weather"]
    end

    test "drops invalid entries before truncating to five" do
      tags = ["", "a", "b", "c", "\x01", "d", "e", "f"]
      assert Metadata.sanitize_tags(tags) == ["a", "b", "c", "d", "e"]
    end

    test "sanitizes non-lists to an empty list" do
      assert Metadata.sanitize_tags(nil) == []
      assert Metadata.sanitize_tags(%{"a" => 1}) == []
    end
  end

  describe "valid_icon_url?/1" do
    test "accepts plain http and https URLs with ports and paths" do
      assert Metadata.valid_icon_url?("http://cdn.example.com:8080/icons/a.png?v=2")
      assert Metadata.valid_icon_url?("https://cdn.example.com")
    end

    test "rejects other schemes, relative URLs, and malformed input" do
      refute Metadata.valid_icon_url?("ftp://cdn.example.com/icon.png")
      refute Metadata.valid_icon_url?("file:///etc/passwd")
      refute Metadata.valid_icon_url?("//cdn.example.com/icon.png")
      refute Metadata.valid_icon_url?("/icon.png")
      refute Metadata.valid_icon_url?("https://")
      refute Metadata.valid_icon_url?("not a url")
      refute Metadata.valid_icon_url?(nil)
    end

    test "rejects loopback names and IP literals in every encoding" do
      for host <- [
            "localhost",
            "LOCALHOST",
            "localhost.localdomain",
            "ip6-localhost",
            "ip6-loopback",
            "127.0.0.1",
            "127.1",
            "10.0.0.1",
            "[::1]",
            "[fe80::1]",
            "2130706433",
            "0x7f000001",
            "0X7F000001",
            "%6c%6f%63%61%6c%68%6f%73%74"
          ] do
        refute Metadata.valid_icon_url?("https://#{host}/icon.png"), host
      end
    end

    test "rejects control characters, non-ASCII hosts, and malformed percent-encoding" do
      refute Metadata.valid_icon_url?("https://cdn.example.com/icon\n.png")
      refute Metadata.valid_icon_url?("https://cdn.example.com/icon\x7F.png")
      refute Metadata.valid_icon_url?("https://bücher.example/icon.png")
      refute Metadata.valid_icon_url?("https://%zz.example/icon.png")
    end

    test "enforces the 2048 character limit" do
      prefix = "https://cdn.example.com/"
      assert Metadata.valid_icon_url?(prefix <> String.duplicate("a", 2048 - byte_size(prefix)))
      refute Metadata.valid_icon_url?(prefix <> String.duplicate("a", 2049 - byte_size(prefix)))
    end
  end

  describe "sanitize_resource/1" do
    test "keeps valid metadata and unrelated keys untouched" do
      resource = %{
        "url" => "https://api.example.com/weather",
        "description" => "Weather",
        "serviceName" => "Example Weather",
        "tags" => ["weather"],
        "iconUrl" => "https://api.example.com/icon.png"
      }

      assert Metadata.sanitize_resource(resource) == resource
    end

    test "drops each invalid field independently" do
      resource = %{
        "url" => "https://api.example.com/weather",
        "serviceName" => String.duplicate("x", 40),
        "tags" => ["", 1],
        "iconUrl" => "javascript:alert(1)"
      }

      assert Metadata.sanitize_resource(resource) == %{"url" => "https://api.example.com/weather"}
    end
  end

  describe "valid_route_template?/1" do
    test "accepts multi-parameter and dotted templates" do
      assert Metadata.valid_route_template?("/weather/:country/:city")
      assert Metadata.valid_route_template?("/files/:name.json")
      assert Metadata.valid_route_template?("/v1.2/items/:id")
    end

    test "rejects empty, relative, and disallowed characters" do
      refute Metadata.valid_route_template?("")
      refute Metadata.valid_route_template?("/")
      refute Metadata.valid_route_template?("/users/{id}")
      refute Metadata.valid_route_template?("/users/:id?x=1")
      refute Metadata.valid_route_template?("/users/ :id")
      refute Metadata.valid_route_template?(nil)
    end

    test "rejects traversal and scheme injection, including percent-encoded forms" do
      refute Metadata.valid_route_template?("/a/..")
      refute Metadata.valid_route_template?("/a/%2E%2E/b")
      refute Metadata.valid_route_template?("/a/https:%2F%2Fevil.example")
      refute Metadata.valid_route_template?("/a/%zz")
    end
  end
end

defmodule EyepatchTest do
  use ExUnit.Case
  doctest Eyepatch
  require Logger

  test "test1" do
    url = "http://ip.xnet.space"
    :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &is_ok_hackney/1])
  end

  test "test2" do
    url = "http://ipv4.xnet.space"
    :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &is_ok_hackney/1])
  end

  def request_hackney(uri, ip_address, _protocol, connect_timeout) do
    ip_address = :inet.ntoa(ip_address)
    opts = [connect_timeout: connect_timeout]
    headers = [{"Host", to_string(uri.host)}]
    uri = %URI{uri | host: to_string(ip_address)} |> URI.to_string()
    Logger.debug("Attempt to connect to URI: #{inspect(uri)}")
    Logger.debug("headers: #{inspect(headers)}")
    Logger.debug("opts: #{inspect(opts)}")
    {:ok, 200, headers, client} = :hackney.request(:get, uri, headers, "", opts)
    :ok = :hackney.close(client)
    {:ok, 200, headers, client}
  end

  def request_ibrowse(uri, ip_address, _protocol, connect_timeout) do
    ip_address = :inet.ntoa(ip_address)
    opts = [connect_timeout: connect_timeout]
    headers = [{"Host", to_string(uri.host)}]

    uri =
      %URI{host: to_string(ip_address), scheme: uri.scheme, path: uri.path} |> URI.to_string()

    Logger.debug("Attempt to connect to URI: #{inspect(uri)}")
    :ibrowse.send_req(uri, headers, :get, "", opts)
  end

  def is_ok_hackney(response) do
    case response do
      {:ok, _, _, _} -> true
      _ -> false
    end
  end
end

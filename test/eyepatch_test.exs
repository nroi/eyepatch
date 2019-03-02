defmodule EyepatchTest do
  use ExUnit.Case
  doctest Eyepatch
  require Logger

  test "connect to ipv4.xnet.space" do
    url = "http://ipv4.xnet.space"
    {duration, _} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &is_ok_hackney/1])
    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "connect to ip.xnet.space" do
    url = "http://ip.xnet.space"
    {duration, _} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &is_ok_hackney/1])
    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "connect to ipv6.xnet.space" do
    url = "http://ipv6.xnet.space"
    {duration, _} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &is_ok_hackney/1])
    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  def request_hackney(uri, ip_address, _protocol, connect_timeout) do
    ip_address = :inet.ntoa(ip_address)
    opts = [connect_timeout: connect_timeout]
    headers = [{"Host", to_string(uri.host)}]
    uri = %URI{uri | host: to_string(ip_address)} |> URI.to_string()
    Logger.debug("Attempt to connect to URI: #{inspect(uri)}")
    {:ok, 200, headers, client} = :hackney.request(:get, uri, headers, "", opts)
    Logger.debug("success!")
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

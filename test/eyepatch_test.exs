defmodule EyepatchTest do
  use ExUnit.Case
  doctest Eyepatch
  require Logger

  @json_path "https://www.archlinux.org/mirrors/status/json/"

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

  test "connect to https://ident.me" do
    url = "https://ident.me"
    {duration, _} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &is_ok_hackney/1])
    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "all mirrors" do
    results = get_mirror_results()
    mirrors = results["urls"]
    http_https_mirrors = Enum.filter(mirrors, fn mirror ->
      case URI.parse(mirror["url"]) do
        %URI{scheme: "https"} -> true
        %URI{scheme: "http"} -> true
        _ -> false
      end
    end)
    Enum.each(http_https_mirrors, fn mirror ->
      url = mirror["url"]
      {duration, _} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &is_ok_hackney/1])
      Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
    end)
  end

  def request_hackney(uri, ip_address, _protocol, connect_timeout) do
    ip_address = :inet.ntoa(ip_address)
    # TODO disabling SSL verification is a workaround made necessary because we connect to IP addresses, not hostnames:
    # If we supply the string "https://<ip-address>" to hackney, the SSL routine will verify if the certificate has
    # been issued to <ip-address>, but certificates are issued to host names, not IP addresses.
    opts = [connect_timeout: connect_timeout, ssl_options: [{:verify, :verify_none}]]
    headers = [{"Host", to_string(uri.host)}]
    uri = %URI{uri | host: to_string(ip_address)} |> URI.to_string()
    Logger.debug("Attempt to connect to URI: #{inspect(uri)}")
    reply = case :hackney.request(:get, uri, headers, "", opts) do
      {:ok, _, headers, client} ->
        Logger.debug("success!")
        :ok = :hackney.close(client)
      {:error, reason} ->
        Logger.debug("Error during connect: #{inspect reason}")
    end
    reply
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

  def get_mirror_results() do
    with {:ok, 200, _headers, client} <- :hackney.request(:get, @json_path) do
      with {:ok, body} <- :hackney.body(client) do
        Jason.decode!(body)
      end
    end
  end
end
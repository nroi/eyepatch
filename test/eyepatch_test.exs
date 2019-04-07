defmodule EyepatchTest do
  use ExUnit.Case
  doctest Eyepatch
  require Logger

  @json_path "https://www.archlinux.org/mirrors/status/json/"

  def test_mirrors(mirrors) do
    mirrors
    # |> Enum.shuffle
    # |> Enum.take(15)
    |> Enum.map(fn mirror ->
      url = mirror["url"]
      {duration, response} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
      {url, {duration, response}}
    end)
  end

  def print_results(results) do
    {successes, failures} = results
    |> Enum.sort(fn {url1, _}, {url2, _} -> url1 <= url2 end)
    |> Enum.split_with(fn {_url, {_duration, result}} ->
         is_ok_hackney?(result)
       end)
    Enum.each(failures, fn {url, {duration, result}} ->
      Logger.debug("mirror: #{url}. duration: #{duration}, result: #{inspect result}")
    end)
    sum_success = Enum.reduce(successes, 0, fn {_url, {duration, _}}, duration_sum -> duration_sum + duration end)
    avg_success = sum_success / Enum.count(successes)
    Logger.debug("Average duration for successful requests: #{avg_success / 1000}")
    Logger.debug("Got #{Enum.count(successes)} successes, #{Enum.count(failures)} failures.")
  end

  test "connect to ipv4.xnet.space" do
    url = "http://ipv4.xnet.space"
    {duration, _} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "connect to ip.xnet.space" do
    url = "http://ip.xnet.space"
    {duration, _} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "connect to ipv6.xnet.space" do
    url = "http://ipv6.xnet.space"
    {duration, _response} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "connect to https://ident.me" do
    url = "https://ident.me"
    {duration, _response} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "connect to https://archlinux.za.mirror.allworldit.com/archlinux/" do
    url = "https://archlinux.za.mirror.allworldit.com/archlinux/"
    {duration, _response} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  @tag :wip
  @tag timeout: 300000
  test "random mirrors" do
    mirrors = get_mirror_results()["urls"]
    http_https_mirrors = Enum.filter(mirrors, fn mirror ->
      case URI.parse(mirror["url"]) do
        %URI{scheme: "https"} -> true
        %URI{scheme: "http"} -> true
        _ -> false
      end
    end)
    results = test_mirrors(http_https_mirrors)
    print_results(results)
  end

  test "random_ipv6_https_mirrors" do
    mirrors = get_mirror_results()["urls"]
    ipv6_https_mirrors = Enum.filter(mirrors, fn mirror ->
      mirror["ipv6"] and case URI.parse(mirror["url"]) do
        %URI{scheme: "https"} -> true
        %URI{} -> false
      end
    end)
    test_mirrors(ipv6_https_mirrors)
  end

  test "http://www.mirrorservice.org/sites/ftp.archlinux.org/" do
    url = "http://www.mirrorservice.org/sites/ftp.archlinux.org/"
    Eyepatch.resolve(url, &request_hackney/4, &check_result_hackney/1)
  end

  test "http://archlinux.polymorf.fr/" do
    url = "http://archlinux.polymorf.fr/"
    Eyepatch.resolve(url, &request_hackney/4, &check_result_hackney/1)
  end

  test "https://mirror.lnx.sk/pub/linux/archlinux/" do
    url = "https://mirror.lnx.sk/pub/linux/archlinux/"
    Eyepatch.resolve(url, &request_hackney/4, &check_result_hackney/1)
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
    reply = :hackney.request(:head, uri, headers, "", opts)
    case reply do
      {:ok, _, _headers} ->
        Logger.debug("Successfully connected to #{uri}")
        # :ok = :hackney.close(client)
      {:error, reason} ->
        Logger.warn("Error while attempting to connect to #{uri}: #{inspect reason}")
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
    :ibrowse.send_req(uri, headers, :head, "", opts)
  end

  def is_ok_hackney?(response) do
    case check_result_hackney(response) do
      :ok -> true
      {:error, _} -> false
    end
  end

  def check_result_hackney(response) do
    case response do
      {:ok, _, _, _} ->
        # GET request is ok
        :ok
      {:ok, _, _} ->
        # HEAD request is ok
        :ok
      other ->
        {:error, other}
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

defmodule EyepatchTest do
  use ExUnit.Case
  doctest Eyepatch
  require Logger

  @json_path "https://www.archlinux.org/mirrors/status/json/"

  def request_hackney_mock_ok(_uri, ip_address, protocol, _connect_timeout) do
    {:ok, {protocol, ip_address, nil, []}}
  end

  def request_hackney_mock_error(_uri, _ip_address, _protocol, _connect_timeout) do
    {:error, :mock}
  end

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
    {successes_ipv6, successes_ipv4} = Enum.split_with(successes, fn
      {_url, {_duration, {:ok, {:inet6, _ip_address, _status, _headers}}}} -> true
      {_url, {_duration, {:ok, {:inet, _ip_address, _status, _headers}}}} -> false
    end)
    sum_success = Enum.reduce(successes, 0, fn {_url, {duration, _}}, duration_sum -> duration_sum + duration end)
    avg_success = sum_success / Enum.count(successes)
    Logger.debug("Average duration for successful requests: #{avg_success / 1000} ms.")
    Logger.debug("Got #{Enum.count(successes)} successes, #{Enum.count(failures)} failures.")
    Logger.debug("Got #{Enum.count(successes_ipv6)} successes over IPv6, #{Enum.count(successes_ipv4)} successes over IPv4.")
  end

  # test "connect to ipv4.xnet.space" do
  #   url = "http://ipv4.xnet.space"
  #   {duration, _} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
  #   Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  # end

  # test "connect to ip.xnet.space" do
  #   url = "http://ip.xnet.space"
  #   {duration, _} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
  #   Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  # end

  # test "connect to ipv6.xnet.space" do
  #   url = "http://ipv6.xnet.space"
  #   {duration, _response} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
  #   Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  # end

  # test "connect to https://ident.me" do
  #   url = "https://ident.me"
  #   {duration, _response} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
  #   Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  # end

  # test "connect to https://archlinux.za.mirror.allworldit.com/archlinux/" do
  #   url = "https://archlinux.za.mirror.allworldit.com/archlinux/"
  #   {duration, _response} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
  #   Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  # end

  # test "https://mirrors.tuna.tsinghua.edu.cn/archlinux/" do
  #   url = "https://mirrors.tuna.tsinghua.edu.cn/archlinux/"
  #   {duration, _response} = :timer.tc(Eyepatch, :resolve, [url, &request_hackney/4, &check_result_hackney/1])
  #   Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  # end

  test "A record exists, AAAA record exists" do
    getaddrs = fn
      _host, :inet -> {:ok, [{78, 46, 175, 29}]}
      _host, :inet6 -> {:ok, [{10753, 1272, 3084, 7656, 0, 0, 0, 2}]}
    end
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_ok/4, &check_result_hackney/1, getaddrs)
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_error/4, &check_result_hackney/1, getaddrs)
  end

  test "A record exists, AAAA record does not exist" do
    getaddrs = fn
      _host, :inet -> {:ok, [{78, 46, 175, 29}]}
      _host, :inet6 -> {:error, :nxdomain}
    end
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_ok/4, &check_result_hackney/1, getaddrs)
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_error/4, &check_result_hackney/1, getaddrs)
  end

  test "A record does not exist, AAAA record exists" do
    getaddrs = fn
      _host, :inet -> {:error, :nxdomain}
      _host, :inet6 -> {:ok, [{10753, 1272, 3084, 7656, 0, 0, 0, 2}]}
    end
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_ok/4, &check_result_hackney/1, getaddrs)
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_error/4, &check_result_hackney/1, getaddrs)
  end

  test "A record does not exist, AAAA record does not exist" do
    getaddrs = fn
      _host, :inet -> {:error, :nxdomain}
      _host, :inet6 -> {:error, :nxdomain}
    end
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_ok/4, &check_result_hackney/1, getaddrs)
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_error/4, &check_result_hackney/1, getaddrs)
  end

  test "Receive A before AAAA, with AAAA within the resolution delay" do
    getaddrs = fn
      _host, :inet ->
        {:ok, [{78, 46, 175, 29}]}
      _host, :inet6 ->
        :timer.sleep(10)
        {:ok, [{10753, 1272, 3084, 7656, 0, 0, 0, 2}]}
    end
    # TODO assert that the resolved ip address is a IPv6 address.
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_ok/4, &check_result_hackney/1, getaddrs)
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_error/4, &check_result_hackney/1, getaddrs)
  end

  test "Receive AAAA before A, with A within the resolution delay" do
    getaddrs = fn
      _host, :inet ->
        :timer.sleep(10)
        {:ok, [{78, 46, 175, 29}]}
      _host, :inet6 ->
        {:ok, [{10753, 1272, 3084, 7656, 0, 0, 0, 2}]}
    end
    # TODO assert that the resolved ip address is a IPv6 address.
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_ok/4, &check_result_hackney/1, getaddrs)
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_error/4, &check_result_hackney/1, getaddrs)
  end

  test "Receive A before AAAA, with AAAA after the resolution delay" do
    getaddrs = fn
      _host, :inet ->
        {:ok, [{78, 46, 175, 29}]}
      _host, :inet6 ->
        :timer.sleep(500)
        {:ok, [{10753, 1272, 3084, 7656, 0, 0, 0, 2}]}
    end
    # TODO assert that the resolved ip address is a IPv6 address.
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_ok/4, &check_result_hackney/1, getaddrs)
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_error/4, &check_result_hackney/1, getaddrs)
  end

  test "Receive AAAA before A, with A after the resolution delay" do
    getaddrs = fn
      _host, :inet ->
        :timer.sleep(500)
        {:ok, [{78, 46, 175, 29}]}
      _host, :inet6 ->
        {:ok, [{10753, 1272, 3084, 7656, 0, 0, 0, 2}]}
    end
    # TODO assert that the resolved ip address is a IPv6 address.
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_ok/4, &check_result_hackney/1, getaddrs)
    Eyepatch.resolve("url_will_be_ignored", &request_hackney_mock_error/4, &check_result_hackney/1, getaddrs)
  end

  def cartesian_product(a, b, c, d, e) do
    for aa <- a, bb <- b, cc <- c, dd <- d, ee <- e do
      {aa, bb, cc, dd, ee}
    end
  end

  @tag :wip2
  test "test all combinations" do
    resolve_ipv4_ok = {:ok, [{78, 46, 175, 29}]}
    resolve_ipv6_ok = {:ok, [{10753, 1272, 3084, 7656, 0, 0, 0, 2}]}
    resolve_error = {:error, :nxdomain}
    resolvers_ipv4 = [{resolve_ipv4_ok, "IPv4 DNS resolver success"}, {resolve_error, "IPv4 DNS resolver error"}]
    resolvers_ipv6 = [{resolve_ipv6_ok, "IPv6 DNS resolver success"}, {resolve_error, "IPv6 DNS resolver error"}]
    within_resolution_delay = fn -> :timer.sleep(10) end
    exceed_resolution_delay = fn -> :timer.sleep(500) end
    no_delay = fn -> :ok end
    sleepers_ipv4 = [
      {within_resolution_delay, "IPv4 within resolution delay"},
      {exceed_resolution_delay, "IPv4 exceeds resolution delay"},
      {no_delay, "IPv4 without delay"},
    ]
    sleepers_ipv6 = [
      {within_resolution_delay, "IPv6 within resolution delay"},
      {exceed_resolution_delay, "IPv6 exceeds resolution delay"},
      {no_delay, "IPv6 without delay"},
    ]
    requester_ipv4 = [
      {&request_hackney_mock_ok/4, "Connection attempt over IPv4 successful"},
      {&request_hackney_mock_error/4, "Connection attempt over IPv4 failed"}
    ]
    requester_ipv6 = [
      {&request_hackney_mock_ok/4, "Connection attempt over IPv4 successful"},
      {&request_hackney_mock_error/4, "Connection attempt over IPv4 failed"}
    ]
    combinations = for aa <- resolvers_ipv4, bb <- resolvers_ipv6, cc <- sleepers_ipv4, dd <- sleepers_ipv6, ee <- requester_ipv4, ff <- requester_ipv6 do
      {aa, bb, cc, dd, ee, ff}
    end

    Enum.each(combinations, fn
      {{ipv4_result, d1}, {ipv6_result, d2}, {ipv4_sleeper, d3}, {ipv6_sleeper, d4}, {requester_ipv4, d5}, {requester_ipv6, d6}} ->
      getaddrs = fn
        _host, :inet ->
          ipv4_sleeper.()
          ipv4_result
        _host, :inet6 ->
          ipv6_sleeper.()
          ipv6_result
      end
      Logger.info("Testing with: #{d1} : #{d2} : #{d3} : #{d4} : #{d5} : #{d6}")
      Eyepatch.resolve("url_will_be_ignored", requester_ipv4, requester_ipv6, &check_result_hackney/1, getaddrs)
    end)
  end


  # def all_combinations() do
  #   resolve_ipv4_ok = {:ok, [{78, 46, 175, 29}]}
  #   resolve_ipv6_ok = {:ok, [{10753, 1272, 3084, 7656, 0, 0, 0, 2}]}
  #   resolve_error = {:error, :nxdomain}
  #   resolvers_ipv4 = [resolve_ipv4_ok, resolve_error]
  #   resolvers_ipv6 = [resolve_ipv6_ok, resolve_error]
  #   within_resolution_delay = fn -> :timer.sleep(10) end
  #   exceed_resolution_delay = fn -> :timer.sleep(500) end
  #   no_delay = fn -> :ok end
  #   sleepers = [within_resolution_delay, exceed_resolution_delay, no_delay]
  #   requester = [&request_hackney_mock_ok/4, &request_hackney_mock_error/4]
  #   cartesian_product(resolvers_ipv4, resolvers_ipv6, sleepers, sleepers, requester)
  # end

  # Enum.each(all_combinations(), fn {ipv4_result, ipv6_result, ipv4_sleeper, ipv6_sleeper, requester} ->
  #   getaddrs = fn
  #     _host, :inet ->
  #       ipv4_sleeper.()
  #       ipv4_result
  #     _host, :inet6 ->
  #       ipv6_sleeper.()
  #       ipv6_result
  #   end
  #   test "#{inspect ipv4_result} #{inspect ipv6_result}, #{ipv4_sleeper}, #{ipv6_sleeper}, #{requester}" do
  #     Eyepatch.resolve("url_will_be_ignored", requester, &check_result_hackney/1, getaddrs)
  #   end
  # end)


  # @tag timeout: 300000
  # test "random mirrors" do
  #   mirrors = get_mirror_results()["urls"]
  #   http_https_mirrors = Enum.filter(mirrors, fn mirror ->
  #     case URI.parse(mirror["url"]) do
  #       %URI{scheme: "https"} -> true
  #       %URI{scheme: "http"} -> true
  #       _ -> false
  #     end
  #   end)
  #   results = test_mirrors(http_https_mirrors)
  #   print_results(results)
  # end

  # test "random_ipv6_https_mirrors" do
  #   mirrors = get_mirror_results()["urls"]
  #   ipv6_https_mirrors = Enum.filter(mirrors, fn mirror ->
  #     mirror["ipv6"] and case URI.parse(mirror["url"]) do
  #       %URI{scheme: "https"} -> true
  #       %URI{} -> false
  #     end
  #   end)
  #   test_mirrors(ipv6_https_mirrors)
  # end

  # test "http://www.mirrorservice.org/sites/ftp.archlinux.org/" do
  #   url = "http://www.mirrorservice.org/sites/ftp.archlinux.org/"
  #   Eyepatch.resolve(url, &request_hackney/4, &check_result_hackney/1)
  # end

  # test "http://archlinux.polymorf.fr/" do
  #   url = "http://archlinux.polymorf.fr/"
  #   Eyepatch.resolve(url, &request_hackney/4, &check_result_hackney/1)
  # end

  # test "https://mirror.lnx.sk/pub/linux/archlinux/" do
  #   url = "https://mirror.lnx.sk/pub/linux/archlinux/"
  #   Eyepatch.resolve(url, &request_hackney/4, &check_result_hackney/1)
  # end

  def request_hackney(uri, ip_address, protocol, connect_timeout) do
    ip_address = :inet.ntoa(ip_address)
    # TODO disabling SSL verification is a workaround made necessary because we connect to IP addresses, not hostnames:
    # If we supply the string "https://<ip-address>" to hackney, the SSL routine will verify if the certificate has
    # been issued to <ip-address>, but certificates are issued to host names, not IP addresses.
    opts = [connect_timeout: connect_timeout, ssl_options: [{:verify, :verify_none}]]
    headers = [{"Host", to_string(uri.host)}]
    uri = %URI{uri | host: to_string(ip_address)} |> URI.to_string()
    Logger.debug("Attempt to connect to URI: #{inspect(uri)}")
    case :hackney.request(:head, uri, headers, "", opts) do
      {:ok, client, headers} ->
        Logger.debug("Successfully connected to #{uri}")
        # protocol is included in the response for logging purposes, so that we can evaluate
        # how often the connection is made via IPv4 and IPv6.
        {:ok, {protocol, ip_address, client, headers}}
      {:error, reason} ->
        Logger.warn("Error while attempting to connect to #{uri}: #{inspect reason}")
        {:error, {protocol, ip_address, reason}}
    end
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
      {:ok, {_protocol, _ip_address, _status, _headers}} -> true
      {:error, _} -> false
    end
  end

  def check_result_hackney(response) do
    response
  end

  def get_mirror_results() do
    with {:ok, 200, _headers, client} <- :hackney.request(:get, @json_path) do
      with {:ok, body} <- :hackney.body(client) do
        Jason.decode!(body)
      end
    end
  end
end

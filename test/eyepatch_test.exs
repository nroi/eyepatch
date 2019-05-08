defmodule EyepatchTest do
  use ExUnit.Case
  doctest Eyepatch
  require Logger

  @json_path "https://www.archlinux.org/mirrors/status/json/"

  def request_hackney_mock_ok(_uri, ip_address, protocol, _connect_timeout, _headers, _pid) do
    {:ok, {protocol, ip_address, nil, []}}
  end

  def request_hackney_mock_error(_uri, _ip_address, _protocol, _connect_timeout, _headers, _pid) do
    {:error, :mock}
  end

  def test_mirrors(mirrors) do
    mirrors
    |> Enum.shuffle()
    |> Enum.map(fn mirror ->
      url = mirror["url"]

      {duration, response} =
        :timer.tc(Eyepatch, :resolve, [
          url,
          request_hackney_inet(),
          request_hackney_inet6(),
          &:inet.getaddrs/2,
          [],
          nil,
          &change_ownership_noop/2
        ])

      {url, {duration, response}}
    end)
  end

  def print_results(results) do
    {successes, failures} =
      results
      |> Enum.sort(fn {url1, _}, {url2, _} -> url1 <= url2 end)
      |> Enum.split_with(fn {_url, {_duration, result}} ->
        is_ok_hackney?(result)
      end)

    Enum.each(failures, fn {url, {duration, result}} ->
      Logger.debug("mirror: #{url}. duration: #{duration}, result: #{inspect(result)}")
    end)

    {successes_ipv6, successes_ipv4} =
      Enum.split_with(successes, fn
        {_url, {_duration, {:ok, {:inet6, _ip_address, _status, _headers}}}} -> true
        {_url, {_duration, {:ok, {:inet, _ip_address, _status, _headers}}}} -> false
      end)

    sum_success =
      Enum.reduce(successes, 0, fn {_url, {duration, _}}, duration_sum ->
        duration_sum + duration
      end)

    avg_success = sum_success / Enum.count(successes)

    {{min_success, min_url}, {max_success, max_url}} =
      Enum.reduce(successes, {nil, nil}, fn
        {url, {duration, _}}, {nil, nil} ->
          {{duration, url}, {duration, url}}

        {url, {duration, _}}, {{min_duration, min_url}, {max_duration, max_url}} ->
          update_min = duration < min_duration
          new_min = (update_min && {duration, url}) || {min_duration, min_url}
          update_max = duration > max_duration
          new_max = (update_max && {duration, url}) || {max_duration, max_url}
          {new_min, new_max}
      end)

    Logger.debug("Average duration for successful requests: #{avg_success / 1000} ms.")

    Logger.debug(
      "Minimum duration for successful requests achieved with url #{min_url}: #{
        min_success / 1000
      } ms."
    )

    Logger.debug(
      "Maximum duration for successful requests achieved with url #{max_url}: #{
        max_success / 1000
      } ms."
    )

    Logger.debug("Got #{Enum.count(successes)} successes, #{Enum.count(failures)} failures.")

    Logger.debug(
      "Got #{Enum.count(successes_ipv6)} successes over IPv6, #{Enum.count(successes_ipv4)} successes over IPv4."
    )
  end

  def change_ownership_noop(_pid, _result), do: :ok

  def change_ownership_hackney(pid, {:ok, {_protocol, conn_ref}}) do
    :ok = :hackney.controlling_process(conn_ref, pid)
  end

  def change_ownership_hackney(_pid, {:error, _}) do
    :ok
  end

  test "connect to ipv4.xnet.space" do
    url = "http://ipv4.xnet.space"

    {duration, _} =
      :timer.tc(Eyepatch, :resolve, [
        url,
        request_hackney_inet(),
        request_hackney_inet6(),
        &:inet.getaddrs/2,
        [],
        nil,
        &change_ownership_noop/2
      ])

    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "connect to ip.xnet.space" do
    url = "http://ip.xnet.space"

    {duration, _} =
      :timer.tc(Eyepatch, :resolve, [
        url,
        request_hackney_inet(),
        request_hackney_inet6(),
        &:inet.getaddrs/2,
        [],
        nil,
        &change_ownership_noop/2
      ])

    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "connect to ipv6.xnet.space" do
    url = "http://ipv6.xnet.space"

    {duration, _} =
      :timer.tc(Eyepatch, :resolve, [
        url,
        request_hackney_inet(),
        request_hackney_inet6(),
        &:inet.getaddrs/2,
        [],
        nil,
        &change_ownership_noop/2
      ])

    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  @tag :wip
  test "connect to https://ident.me" do
    url = "https://ident.me"

    {duration, result} =
      :timer.tc(Eyepatch, :resolve, [
        url,
        connect_hackney_inet(),
        connect_hackney_inet6(),
        &:inet.getaddrs/2,
        [],
        nil,
        &change_ownership_hackney/2
      ])

    {:ok, {_protocol, conn_ref}} = result
    headers = [{"Host", "ident.me"}]
    req = {:get, "/", headers, ""}
    for _ <- 1..10 do
      {:ok, _, _, ^conn_ref} = :hackney.send_request(conn_ref, req)
      {:ok, body} = :hackney.body(conn_ref)
      Logger.debug("Got body: #{inspect body}")
    end
    :ok = :hackney.close(conn_ref)

    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  test "connect to https://ident.me and GET body" do
    url = "https://ident.me"

    {duration, _} =
      :timer.tc(Eyepatch, :resolve, [
        url,
        request_hackney_inet(),
        request_hackney_inet6(),
        &:inet.getaddrs/2,
        [],
        nil,
        &change_ownership_noop/2
      ])

    Logger.info("Duration for #{url} in milliseconds: #{duration / 1000}")
  end

  @tag timeout: 500_000
  @tag :wip
  test "random mirrors" do
    mirrors = get_mirror_results()["urls"]

    http_https_mirrors =
      Enum.filter(mirrors, fn mirror ->
        case URI.parse(mirror["url"]) do
          %URI{scheme: "https"} -> true
          %URI{scheme: "http"} -> true
          _ -> false
        end
      end)

    results = test_mirrors(http_https_mirrors)
    print_results(results)
  end

  test "test all combinations" do
    resolve_ipv4_ok = {:ok, [{78, 46, 175, 29}]}
    resolve_ipv6_ok = {:ok, [{10753, 1272, 3084, 7656, 0, 0, 0, 2}]}
    resolve_error = {:error, :nxdomain}

    resolvers_ipv4 = [
      {resolve_ipv4_ok, "IPv4 DNS resolver success"},
      {resolve_error, "IPv4 DNS resolver error"}
    ]

    resolvers_ipv6 = [
      {resolve_ipv6_ok, "IPv6 DNS resolver success"},
      {resolve_error, "IPv6 DNS resolver error"}
    ]

    within_resolution_delay = fn -> :timer.sleep(10) end
    exceed_resolution_delay = fn -> :timer.sleep(500) end
    no_delay = fn -> :ok end

    sleepers_ipv4 = [
      {within_resolution_delay, "IPv4 within resolution delay"},
      {exceed_resolution_delay, "IPv4 exceeds resolution delay"},
      {no_delay, "IPv4 without delay"}
    ]

    sleepers_ipv6 = [
      {within_resolution_delay, "IPv6 within resolution delay"},
      {exceed_resolution_delay, "IPv6 exceeds resolution delay"},
      {no_delay, "IPv6 without delay"}
    ]

    requester_ipv4 = [
      {&request_hackney_mock_ok(&1, &2, :inet, &3, &4, &5),
       "Connection attempt over IPv4 successful"},
      {&request_hackney_mock_error(&1, &2, :inet, &3, &4, &5),
       "Connection attempt over IPv4 failed"}
    ]

    requester_ipv6 = [
      {&request_hackney_mock_ok(&1, &2, :inet6, &3, &4, &5),
       "Connection attempt over IPv6 successful"},
      {&request_hackney_mock_error(&1, &2, :inet6, &3, &4, &5),
       "Connection attempt over IPv6 failed"}
    ]

    combinations =
      for aa <- resolvers_ipv4,
          bb <- resolvers_ipv6,
          cc <- sleepers_ipv4,
          dd <- sleepers_ipv6,
          ee <- requester_ipv4,
          ff <- requester_ipv6 do
        {aa, bb, cc, dd, ee, ff}
      end

    Enum.each(combinations, fn
      {{ipv4_result, d1}, {ipv6_result, d2}, {ipv4_sleeper, d3}, {ipv6_sleeper, d4},
       {requester_ipv4, d5}, {requester_ipv6, d6}} ->
        getaddrs = fn
          _host, :inet ->
            ipv4_sleeper.()
            ipv4_result

          _host, :inet6 ->
            ipv6_sleeper.()
            ipv6_result
        end

        Logger.info("Testing with: #{d1} : #{d2} : #{d3} : #{d4} : #{d5} : #{d6}")

        Eyepatch.resolve(
          "url_will_be_ignored",
          requester_ipv4,
          requester_ipv6,
          getaddrs,
          [],
          nil,
          &change_ownership_noop/2
        )
    end)
  end

  def request_hackney(method, uri, ip_address, protocol, connect_timeout, headers, _pid)
      when method == :get or method == :head do
    ip_address =
      case :inet.ntoa(ip_address) do
        {:error, :einval} -> raise("Unable to parse ip address: #{inspect(ip_address)}")
        x -> x
      end

    # TODO disabling SSL verification is a workaround made necessary because we connect to IP addresses, not hostnames:
    # If we supply the string "https://<ip-address>" to hackney, the SSL routine will verify if the certificate has
    # been issued to <ip-address>, but certificates are issued to host names, not IP addresses.
    # TODO if it's able to tell hackney "connect ONLY via IPv4" or "connect ONLY via IPv6", we won't need that
    # workaround.
    opts = [connect_timeout: connect_timeout, ssl_options: [{:verify, :verify_none}]]
    headers = [{"Host", to_string(uri.host)} | headers]
    uri = %URI{uri | host: to_string(ip_address)} |> URI.to_string()
    Logger.debug("Attempt to connect to URI: #{inspect(uri)}")

    case :hackney.request(method, uri, headers, "", opts) do
      {:ok, status, headers} ->
        Logger.debug("Successfully connected to #{uri}")
        # protocol is included in the response for logging purposes, so that we can evaluate
        # how often the connection is made via IPv4 and IPv6.
        {:ok, {protocol, ip_address, status, headers}}

      {:error, reason} ->
        Logger.warn("Error while attempting to connect to #{uri}: #{inspect(reason)}")
        {:error, {protocol, ip_address, reason}}
    end
  end

  def request_hackney_inet(), do: &request_hackney(:head, &1, &2, :inet, &3, &4, &5)
  def request_hackney_inet6(), do: &request_hackney(:head, &1, &2, :inet6, &3, &4, &5)
  def connect_hackney_inet(), do: &connect_hackney(:head, &1, &2, :inet, &3, &4, &5)
  def connect_hackney_inet6(), do: &connect_hackney(:head, &1, &2, :inet6, &3, &4, &5)

  def request_ibrowse(uri, ip_address, _protocol, connect_timeout) do
    ip_address = :inet.ntoa(ip_address)
    opts = [connect_timeout: connect_timeout]
    headers = [{"Host", to_string(uri.host)}]

    uri = %URI{host: to_string(ip_address), scheme: uri.scheme, path: uri.path} |> URI.to_string()

    Logger.debug("Attempt to connect to URI: #{inspect(uri)}")
    :ibrowse.send_req(uri, headers, :head, "", opts)
  end

  def is_ok_hackney?(response) do
    case response do
      {:ok, {_protocol, _ip_address, _status, _headers}} -> true
      {:error, _} -> false
      :timeout_exceeded -> false
    end
  end

  def get_mirror_results() do
    with {:ok, 200, _headers, client} <- :hackney.request(:get, @json_path) do
      with {:ok, body} <- :hackney.body(client) do
        Jason.decode!(body)
      end
    end
  end

  def connect_hackney(_method, uri, ip_address, protocol, connect_timeout, _headers, _pid) do
    ip_address =
      case :inet.ntoa(ip_address) do
        {:error, :einval} -> raise("Unable to parse ip address: #{inspect(ip_address)}")
        x -> x
      end
    Logger.debug("ip is: #{inspect ip_address}, protocol: #{protocol}")

    opts = [connect_timeout: connect_timeout, ssl_options: [{:verify, :verify_none}]]
    transport = case uri.port do
      80 -> :hackney_tcp
      443 -> :hackney_ssl
    end
    case :hackney.connect(transport, ip_address, uri.port, opts) do
      {:ok, conn_ref} ->
        Logger.debug("Successfully connected to #{uri.host} via #{inspect ip_address}")
        {:ok, {protocol, conn_ref}}
      {:error, reason} ->
        Logger.warn("Error while attempting to connect to #{uri.host}: #{inspect(reason)}")
        {:error, {protocol, reason}}
    end
  end

end

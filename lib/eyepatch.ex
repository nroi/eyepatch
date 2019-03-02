defmodule Eyepatch do
  # https://tools.ietf.org/html/rfc8305

  # The recommended value for the Resolution Delay is 50 milliseconds.
  @resolution_delay 50

  # One recommended value for a default [connection attempt] delay is 250 milliseconds.
  @connection_attempt_delay 250

  @success_ipv4_msg "Successfully connected via IPv4."
  @success_ipv6_msg "Successfully connected via IPv6."

  @error_ipv6_fallback_ipv4_msg "Error while attempting to connect via IPv6. Trying IPv4 instead…"
  @error_ipv4_msg "Error while attempting to connect via IPv4."

  require Logger

  @moduledoc """
  Dual stack connection establishment. Hopefully, this will one day be extended to a full
  happy eyeballs implementation.

  names: eyepatch, blackeye?
  """

  def resolve(url, request_fn, is_ok) do
    # When a client has both IPv4 and IPv6 connectivity and is trying to
    # establish a connection with a named host, it needs to send out both
    # AAAA and A DNS queries.  Both queries SHOULD be made as soon after
    # one another as possible, with the AAAA query made first and
    # immediately followed by the A query.

    Logger.debug("Attempt to resolve url #{url}")

    uri = URI.parse(url)

    protocols = [:inet6, :inet]

    Logger.debug("Starting dns resolution for both protocols")

    Enum.each(protocols, fn protocol ->
      Task.async(fn ->
        case :inet.getaddrs(to_charlist(uri.host), protocol) do
          {:ok, [ip_address | _ignored]} ->
            # TODO for now, we just ignore all results except for the first.
            Logger.debug("Successful DNS resolution for #{protocol}")
            {:dns_reply, {protocol, {:ok, ip_address}}}

          {:error, reason} ->
            Logger.error("DNS resolution failed for #{protocol}")
            {:dns_reply, {protocol, {:error, reason}}}
        end
      end)
    end)

    # two cases:
    #   A: We have a IPv4 address. That means we have unsuccessfully tried to obtain an IPv6 address within the
    #      resolution delay. A correct implementation of happy eyeballs would still have a chance of using IPv6,
    #      in case the IPv4 connection attempts are unsuccessful and we receive an IPv6 address during our
    #      unsuccessful IPv4 connection attempts. Instead, we just try to connect via IPv4 and return an error
    #      if that fails.
    #   B: We have an IPv6 address. Since many hosts still have buggy implementations of IPv6, we try an IPv4 address
    #      if the connection via IPv6 fails.

    reply = get_dns_reply()

    case reply do
      {inet6_reply = {:inet6, {:ok, _ip_address}}, _fallback} ->
        result = connect(inet6_reply, uri, request_fn)

        if is_ok.(result) do
          Logger.debug(@success_ipv6_msg)
        else
          Logger.error(@error_ipv6_fallback_ipv4_msg)

          if is_ok.(result) do
            Logger.debug(@success_ipv4_msg)
          else
            Logger.error(@error_ipv4_msg)
          end
        end

        result

      {{:inet6, {:error, _reason}}, fallback = {:fallback, {:inet, _result}}} ->
        result = connect_ipv4_fallback(fallback, uri, request_fn)

        if is_ok.(result) do
          Logger.debug(@success_ipv4_msg)
        else
          Logger.error(@error_ipv4_msg)
        end

        result

      {inet_reply = {:inet, {:ok, _ip_address}}, {:fallback, nil}} ->
        result = connect(inet_reply, uri, request_fn)

        if is_ok.(result) do
          Logger.debug(@success_ipv4_msg)
        else
          Logger.error(@error_ipv4_msg)
        end

        result
    end
  end

  def get_dns_reply(ipv6_has_failed \\ false) do
    receive do
      {_, {:dns_reply, reply = {:inet, {:ok, _ip_address}}}} ->
        if ipv6_has_failed do
          Logger.debug("Received inet DNS response after inet6 DNS failure. Will use inet.")
          {reply, {:fallback, nil}}
        else
          # If a positive A response is received first due to reordering, the client SHOULD
          # wait a short time for the AAAA response to ensure that preference is
          # given to IPv6 (it is common for the AAAA response to follow the A
          # response by a few milliseconds). This delay will be referred to as
          # the "Resolution Delay".
          wait_ipv6_or_else(reply)
        end

      {_, {:dns_reply, reply = {:inet6, {:ok, _ip_address}}}} ->
        {reply, {:fallback, {:inet, nil}}}

      {_, {:dns_reply, {:inet, {:error, _reason}}}} ->
        if ipv6_has_failed do
          raise("DNS resolution failed for both inet and inet6.")
        else
          get_dns_reply(true)
        end

      {_, {:dns_reply, {:inet6, {:error, _reason}}}} ->
        if ipv6_has_failed do
          raise("DNS resolution failed for both inet and inet6.")
        else
          get_dns_reply(true)
        end
    end
  end

  def connect_ipv4_fallback({:fallback, {:inet, nil}}, uri, request_fn) do
    Logger.debug("Attempt to connect via IPv4, but fallback is nil.")
    # We still haven't received the IPv4 address, but already sent the DNS request.
    receive do
      {_, {:dns_reply, inet_reply = {:inet, _ip_address}}} ->
        connect(inet_reply, uri, request_fn)
    end
  end

  def connect_ipv4_fallback({:fallback, inet_reply = {:inet, _ip_address}}, uri, request_fn) do
    connect(inet_reply, uri, request_fn)
  end

  def connect({protocol, {:ok, ip_address}}, uri = %URI{}, request_fn)
      when protocol == :inet or protocol == :inet6 do
    connect_to_url(uri, ip_address, protocol, request_fn)
  end

  def connect_to_url(uri = %URI{}, ip_address, protocol, request_fn)
      when protocol == :inet or protocol == :inet6 do
    request_fn.(uri, ip_address, protocol, @connection_attempt_delay)
  end

  # We have already received an IPv4 DNS reply, but there's still a chance for an IPv6 DNS reply to arrive.
  def wait_ipv6_or_else(ipv4_reply) do
    receive do
      {_, {:dns_reply, reply = {:inet6, {:ok, _ip_address}}}} ->
        Logger.debug("Received inet6 within resolution delay. Will store inet as fallback.")
        {reply, {:fallback, ipv4_reply}}

      {_, {:dns_reply, reply = {:inet6, {:error, reason}}}} ->
        Logger.debug("Failure to resolve IPv6: #{inspect(reason)}. Will use IPv4 instead.")
        {reply, {:fallback, ipv4_reply}}
    after
      @resolution_delay ->
        Logger.debug("Didn't receive inet6 within resolution delay. Will stick with inet.")
        {ipv4_reply, {:fallback, nil}}
    end
  end

  def test1() do
    url = "http://ip.xnet.space"
    :timer.tc(__MODULE__, :resolve, [url])
  end


end